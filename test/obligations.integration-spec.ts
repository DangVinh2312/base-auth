import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import {
  type AuthorizedPlan,
  parseKey,
  plan,
  type TrustedInput,
  validate,
} from '@base-authorization/core';
import {
  BindingRegistry,
  DataGateway,
  fulfillObligations,
  type ObligationHandler,
  PostgresAuthority,
  type TenantTransaction,
  TenantTransactionRunner,
} from '@base-authorization/typeorm-postgres';
import type pg from 'pg';
import { AuditOutboxService } from '../apps/api/dist/audit/audit-outbox.service.js';
import {
  alice,
  declarationsSource,
  type GatewayEnvironment,
  startGatewayEnvironment,
  storageBindings,
  tenantA,
} from './fixtures/resources.ts';
import { openClient } from './setup-postgres.ts';

const bytes = (value: string) => Buffer.from(value, 'utf8');

describe('obligations and the audit outbox', () => {
  let env: GatewayEnvironment;
  let authority: PostgresAuthority;
  let gateway: DataGateway;
  let admin: pg.Client;
  const outbox = new AuditOutboxService();

  // Approve carries a mandatory audit obligation in this variant of the fixture manifest.
  const result = validate({
    ...declarationsSource,
    policies: declarationsSource.policies.map((p) =>
      p.key === 'approval' ? { ...p, obligations: [{ handler: 'auditApproval@1' }] } : p,
    ),
    capabilities: { validators: [], obligationHandlers: ['auditApproval@1'] },
  });
  if (!result.ok) throw new Error(result.errors.join('; '));
  const declarations = result.declarations;

  before(async () => {
    env = await startGatewayEnvironment();
    const runner = new TenantTransactionRunner(env.registry);
    authority = new PostgresAuthority(runner, declarations, {
      validators: {},
      obligationHandlers: ['auditApproval@1'],
    });
    gateway = new DataGateway(new BindingRegistry(declarations, storageBindings));
    admin = await openClient(env.adminOn(tenantA));
    await admin.query(
      `INSERT INTO policy_rule VALUES ($1, gen_random_uuid(), $2, NULL, $3, 'allow', $4, 1, '{}', 'tenant')`,
      [tenantA, bytes('submission.approve'), bytes('reviewer'), bytes('all')],
    );
  });
  after(async () => {
    await admin?.end();
    await env?.stop();
  });

  const approveInput = (): TrustedInput => {
    const now = new Date();
    return {
      tenant: tenantA,
      principal: { id: alice, assurance: 2 },
      resource: 'submission',
      action: 'approve',
      context: {},
      now: now.toISOString(),
      validUntil: new Date(now.getTime() + 60_000).toISOString(),
    };
  };
  const auditRows = async (kind: string) =>
    (
      await admin.query<{ r: string }>(
        'SELECT policy_revision::text AS r FROM audit_outbox WHERE event_kind = $1',
        [bytes(kind)],
      )
    ).rows;

  /** Read under an approve plan: payload is returned only after obligations ran and committed. */
  const approveRead = (handlers: Readonly<Record<string, ObligationHandler>>, mutate = false) =>
    authority.withSnapshot({ id: alice, assurance: 2 }, tenantA, 'write', async (snapshot, tx) => {
      const decision = plan(approveInput(), snapshot);
      assert.equal(decision.effect, 'allow');
      if (decision.effect !== 'allow') return null;
      assert.deepEqual(decision.obligations, [{ handler: 'auditApproval@1' }]);
      if (mutate) {
        await tx.manager.query(`INSERT INTO object_ref VALUES ($1, $2, $3, 'integer', $4)`, [
          tenantA,
          '99000000-0000-4000-8000-000000000001',
          bytes('submission'),
          bytes('424242'),
        ]);
      }
      const row = await gateway.detail(decision.plan, parseKey('integer', '1'), tx);
      await fulfillObligations(decision.plan, tx, handlers);
      return row;
    });
  const audit =
    (kind: string, eventId: () => string = randomUUID) =>
    (tx: TenantTransaction, authorized: AuthorizedPlan) =>
      outbox.append(tx, {
        eventId: eventId(),
        actorId: authorized.identity,
        kind,
        permission: authorized.permission,
        metadata: { resource: authorized.resource },
      });

  test('the audit event commits with the result and records the authority revision', async () => {
    const row = await approveRead({ 'auditApproval@1': audit('submission.approve') });
    assert.equal(row?.key, '1');
    const revision = (
      await admin.query<{ r: string }>('SELECT revision::text AS r FROM authz_fence')
    ).rows[0]!.r;
    assert.deepEqual(await auditRows('submission.approve'), [{ r: revision }]);
  });

  test('a failed audit insert rolls back the effect and releases no payload', async () => {
    const duplicate = randomUUID();
    await approveRead({ 'auditApproval@1': audit('audit.dup', () => duplicate) });
    await assert.rejects(
      approveRead({ 'auditApproval@1': audit('audit.dup', () => duplicate) }, true),
    );
    assert.equal((await auditRows('audit.dup')).length, 1);
    const objects = await admin.query(`SELECT 1 FROM object_ref WHERE key_bytes = $1`, [
      bytes('424242'),
    ]);
    assert.equal(objects.rowCount, 0, 'mutation in the same transaction was rolled back');
  });

  test('invalid audit events are rejected before reaching SQL', async () => {
    for (const bad of [
      { kind: 'Bad Kind' },
      { eventId: 'not-a-uuid' },
      { metadata: { nested: { secret: 'x' } } as never },
      { metadata: { blob: 'x'.repeat(5_000) } },
    ]) {
      await assert.rejects(
        approveRead({
          'auditApproval@1': (tx, authorized) =>
            outbox.append(tx, {
              eventId: randomUUID(),
              actorId: authorized.identity,
              kind: 'submission.approve',
              ...bad,
            }),
        }),
        TypeError,
      );
    }
  });

  test('a missing obligation handler denies instead of returning data', async () => {
    await assert.rejects(approveRead({}), /obligation/i);
  });
});
