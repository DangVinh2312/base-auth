import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import type { IdentityId, TrustedInput } from '@base-authorization/core';
import { TransactionConflictError } from '@base-authorization/typeorm-postgres';
import {
  AuthorityUnavailableError,
  BindingRegistry,
  DataGateway,
  PostgresAuthority,
  tenantRoleName,
  TenantTransactionRunner,
} from '@base-authorization/typeorm-postgres/legacy';
import type pg from 'pg';
import {
  alice,
  bob,
  fixtureDeclarations,
  type GatewayEnvironment,
  startGatewayEnvironment,
  storageBindings,
  tenantA,
  core,
} from './fixtures/resources.ts';
import { openClient, withClient } from './setup-postgres.ts';

const { plan } = core;

const bytes = (value: string) => Buffer.from(value, 'utf8');

describe('tenant fence, revocation and transaction limits', () => {
  let env: GatewayEnvironment;
  let runner: TenantTransactionRunner;
  let authority: PostgresAuthority;
  let gateway: DataGateway;
  let admin: pg.Client;
  let monitor: pg.Client;

  before(async () => {
    env = await startGatewayEnvironment();
    runner = new TenantTransactionRunner(env.registry, { deadlineMs: 2_000, lockTimeoutMs: 1_500 });
    authority = new PostgresAuthority(core, runner, fixtureDeclarations(), {
      validators: {},
      obligationHandlers: [],
    });
    gateway = new DataGateway(new BindingRegistry(core, fixtureDeclarations(), storageBindings));
    admin = await openClient(env.adminOn(tenantA));
    monitor = await openClient(env.postgres.superuser);
    await admin.query(
      `INSERT INTO policy_rule VALUES ($1, gen_random_uuid(), $2, NULL, $3, 'allow', $4, 1, '{}', 'tenant'),
                                     ($1, gen_random_uuid(), $2, $5, NULL, 'allow', $6, 1, '{}', 'tenant')`,
      [
        tenantA,
        bytes('submission.read'),
        bytes('reviewer'),
        bytes('all'),
        bob,
        bytes('assignedToMe'),
      ],
    );
  });
  after(async () => {
    await admin?.end();
    await monitor?.end();
    await env?.stop();
  });

  const input = (identity: IdentityId): TrustedInput => {
    const now = new Date();
    return {
      tenant: tenantA,
      principal: { id: identity, assurance: 2 },
      resource: 'submission',
      action: 'read',
      context: {},
      now: now.toISOString(),
      validUntil: new Date(now.getTime() + 60_000).toISOString(),
    };
  };

  /** One authorization: fence → authority facts → plan → gateway, all in one transaction. */
  const readIds = (
    identity: IdentityId,
    hold?: {
      acquired: () => void;

      gate: Promise<void>;
    },
  ) =>
    authority.withSnapshot(
      { id: identity, assurance: 2 },
      tenantA,
      'read',
      async (snapshot, tx) => {
        const decision = plan(input(identity), snapshot);
        const ids =
          decision.effect === 'deny'
            ? []
            : (await gateway.list(decision.plan, { limit: 100 }, tx)).items
                .map((i) => i.key)
                .sort();
        if (hold) {
          hold.acquired();
          await hold.gate;
        }
        return ids;
      },
    );

  const revision = async () =>
    (await admin.query<{ r: string }>('SELECT revision::text AS r FROM authz_fence')).rows[0]!.r;

  // Other roles' wait events are visible only to privileged monitors.
  const waitingOnLock = async (role: string) => {
    for (let i = 0; i < 50; i++) {
      const rows = await monitor.query(
        `SELECT 1 FROM pg_stat_activity WHERE usename = $1 AND wait_event_type = 'Lock'`,
        [role],
      );
      if (rows.rowCount) return true;
      await sleep(20);
    }
    return false;
  };

  async function assertRevocation(
    identity: IdentityId,
    revokeSql: string,
    params: unknown[],
    lost: string,
  ) {
    const before = await readIds(identity);
    assert.ok(before.includes(lost), `fixture: ${lost} visible before revoke`);

    let acquired!: () => void;
    let open!: () => void;
    const ready = new Promise<void>((resolve) => (acquired = resolve));
    const gate = new Promise<void>((resolve) => (open = resolve));
    const inFlight = readIds(identity, { acquired, gate });
    await ready;

    const revisionBefore = await revision();
    let committed = false;
    let factsTouched = false;
    const revoke = runner
      .run(tenantA, 'admin', async (tx) => {
        factsTouched = true; // runs only after the exclusive fence was granted
        await tx.manager.query(revokeSql, params);
      })
      .then(() => (committed = true));
    assert.ok(
      await waitingOnLock(tenantRoleName(tenantA, 'authority')),
      'revoke waits for the shared fence',
    );
    assert.equal(
      factsTouched,
      false,
      'exclusive fence is taken before any authority fact is read or written',
    );
    assert.equal(committed, false);

    open();
    assert.deepEqual(
      await inFlight,
      before,
      'request admitted before the revoke keeps its snapshot',
    );
    await revoke;
    assert.equal(
      BigInt(await revision()),
      BigInt(revisionBefore) + 1n,
      'exclusive transaction bumps revision',
    );

    const after = await readIds(identity);
    assert.ok(
      !after.includes(lost),
      `authorization started after revoke commit must not see ${lost}`,
    );
  }

  test('removing a role waits for in-flight readers and denies requests started after commit', async () => {
    await assertRevocation(
      alice,
      'DELETE FROM member_role WHERE tenant_id = $1 AND identity_id = $2 AND role_key = $3',
      [tenantA, alice, bytes('reviewer')],
      '1',
    );
    await runner.run(tenantA, 'admin', (tx) =>
      tx.manager.query('INSERT INTO member_role VALUES ($1, $2, $3)', [
        tenantA,
        alice,
        bytes('reviewer'),
      ]),
    );
  });

  test('inserting a deny rule that did not exist yet follows the same fence', async () => {
    const ruleId = randomUUID();
    await assertRevocation(
      alice,
      `INSERT INTO policy_rule VALUES ($1, $2, $3, $4, NULL, 'deny', $5, 1, $6, 'tenant')`,
      [
        tenantA,
        ruleId,
        bytes('submission.read'),
        alice,
        bytes('statusIs'),
        JSON.stringify({ status: 'pending' }),
      ],
      '1',
    );
    await runner.run(tenantA, 'admin', (tx) =>
      tx.manager.query('DELETE FROM policy_rule WHERE rule_id = $1', [ruleId]),
    );
  });

  test('deleting a relation edge follows the same fence', async () => {
    await assertRevocation(
      bob,
      'DELETE FROM identity_relation WHERE tenant_id = $1 AND identity_id = $2',
      [tenantA, bob],
      '5',
    );
  });

  test('statement deadline is enforced by the database', async () => {
    const started = Date.now();
    await assert.rejects(
      runner.run(tenantA, 'read', (tx) => tx.manager.query('SELECT pg_sleep(5)')),
      AuthorityUnavailableError,
    );
    assert.ok(Date.now() - started < 3_000);
  });

  test('transaction deadline is enforced by the database across statements', async () => {
    const started = Date.now();
    await assert.rejects(
      runner.run(tenantA, 'read', async (tx) => {
        await tx.manager.query('SELECT pg_sleep(1.2)');
        await tx.manager.query('SELECT pg_sleep(1.2)');
      }),
      AuthorityUnavailableError,
    );
    assert.ok(Date.now() - started < 3_500);
    assert.ok((await readIds(alice)).length > 0, 'pool recovers after the session was terminated');
  });

  test('lock timeout is retried at most twice, then a conflict is reported', async () => {
    const retries: string[] = [];
    const impatient = new TenantTransactionRunner(env.registry, {
      lockTimeoutMs: 300,

      onRetry: (code) => {
        retries.push(code);
      },
    });
    const holder = await openClient(env.adminOn(tenantA));
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT 1 FROM authz_fence FOR UPDATE');
      await assert.rejects(
        impatient.run(tenantA, 'read', () => Promise.resolve()),
        TransactionConflictError,
      );
      assert.deepEqual(retries, ['55P03', '55P03']);
    } finally {
      await holder.query('ROLLBACK');
      await holder.end();
    }
  });

  test('a retried transaction does not repeat its side effect', async () => {
    const holder = await openClient(env.adminOn(tenantA));
    await holder.query('BEGIN');
    await holder.query('SELECT pg_advisory_xact_lock(4242)');
    let attempts = 0;
    const retrying = new TenantTransactionRunner(env.registry, {
      lockTimeoutMs: 300,

      onRetry: () => holder.query('ROLLBACK').then(() => undefined),
    });
    try {
      await retrying.run(tenantA, 'write', async (tx) => {
        attempts++;
        await tx.manager.query(
          `INSERT INTO audit_outbox VALUES ($1, $2, $3, $4, NULL, NULL, $5, clock_timestamp(), NULL, '{}', NULL)`,
          [tenantA, randomUUID(), alice, bytes('retry.probe'), tx.revision],
        );
        await tx.manager.query('SELECT pg_advisory_xact_lock(4242)');
      });
    } finally {
      await holder.end();
    }
    assert.equal(attempts, 2);
    const rows = await admin.query('SELECT 1 FROM audit_outbox WHERE event_kind = $1', [
      bytes('retry.probe'),
    ]);
    assert.equal(rows.rowCount, 1);
  });

  test('a dropped connection aborts the transaction and is not retried', async () => {
    let attempts = 0;
    await assert.rejects(
      runner.run(tenantA, 'write', async (tx) => {
        attempts++;
        const [backend] = await tx.manager.query<{ pid: number }[]>(
          'SELECT pg_backend_pid() AS pid',
        );
        await withClient(env.postgres.superuser, (c) =>
          c.query('SELECT pg_terminate_backend($1)', [backend?.pid]),
        );
        await tx.manager.query(
          `INSERT INTO audit_outbox VALUES ($1, $2, $3, $4, NULL, NULL, 1, clock_timestamp(), NULL, '{}', NULL)`,
          [tenantA, randomUUID(), alice, bytes('disconnect.probe')],
        );
      }),
      AuthorityUnavailableError,
    );
    assert.equal(attempts, 1);
    const rows = await admin.query('SELECT 1 FROM audit_outbox WHERE event_kind = $1', [
      bytes('disconnect.probe'),
    ]);
    assert.equal(rows.rowCount, 0);
    assert.ok((await readIds(alice)).length > 0);
  });
});
