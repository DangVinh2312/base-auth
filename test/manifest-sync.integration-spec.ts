import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { type IdentityId, parseTenantId, type TenantId } from '@base-authorization/core';
import {
  type ConnectionPurpose,
  directoryRouteResolver,
  identityDataSourceOptions,
  ManifestReconciler,
  prepareRelease,
  ReleaseRejectedError,
  type ReleaseSource,
  TenantDataSourceRegistry,
  tenantDatabaseName,
  TenantProvisioner,
  tenantRoleName,
  TenantTransactionRunner,
} from '@base-authorization/typeorm-postgres';
import type pg from 'pg';
import { DataSource } from 'typeorm';
import { declarationsSource } from './fixtures/resources.ts';
import {
  type Connection,
  openClient,
  sqlState,
  startPostgres,
  type TestPostgres,
  withClient,
} from './setup-postgres.ts';

const tenantA = parseTenantId('00000000-0000-4000-8000-0000000000a8');
const tenantB = parseTenantId('00000000-0000-4000-8000-0000000000b8');
const deployer = 'd0000000-0000-4000-8000-00000000000d' as IdentityId;
const bytes = (value: string) => Buffer.from(value, 'utf8');
const capabilities = { validators: [], obligationHandlers: [] };
const submissionKey = '9007199254740993';
const siteKey = 'd97eecc9-8f23-4a76-a9aa-82b9d4ef33ac';
const otherSiteKey = '5e0c2f1e-3b7a-4c1d-9f0e-1a2b3c4d5e6f';

/** Release content builder: the D1-like fixture manifest plus code roles, defaults and seeds. */
function release(
  sequence: string,
  predecessor: string,
  changes: Partial<ReleaseSource> = {},
): ReleaseSource {
  return {
    sequence,
    predecessor,
    declarations: declarationsSource,
    roles: [
      { key: 'reviewer', authorityLevel: 10, label: 'Reviewer' },
      { key: 'manager', authorityLevel: 50, label: 'Manager' },
    ],
    defaultGrants: [
      {
        permission: 'submission.read',
        role: 'reviewer',
        template: { key: 'assignedToMe', version: 1 },
        parameters: {},
      },
      {
        permission: 'site.read',
        role: 'manager',
        template: { key: 'mySites', version: 1 },
        parameters: {},
      },
    ],
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
    ...changes,
  };
}
const seed = (owner: string, key: string, target = siteKey) => ({
  owner,
  key,
  relation: { key: 'submission.site', version: 1 },
  source: { type: 'submission', key: { kind: 'integer' as const, value: submissionKey } },
  target: { type: 'site', key: { kind: 'uuid' as const, value: target } },
  startsAt: '2026-10-12T00:00:00.000000Z',
});
// Release 2: approval@2 replaces approval@1 for approve, new export action with a default grant.
const v2Source = {
  ...declarationsSource,
  resources: declarationsSource.resources.map((r) =>
    r.key === 'submission'
      ? {
          ...r,
          actions: {
            ...r.actions,
            approve: { policy: { key: 'approval', version: 2 }, boundary: 'optional' as const },
            export: { policy: { key: 'baseline', version: 1 }, boundary: 'optional' as const },
          },
        }
      : r,
  ),
  policies: [
    ...declarationsSource.policies,
    {
      key: 'approval',
      version: 2,
      contextRequirements: [],
      requiredScope: {
        op: 'eq' as const,
        field: 'archived',
        value: { from: 'literal' as const, value: false },
      },
      obligations: [],
    },
  ],
};
const r1 = prepareRelease(release('1', '0'));
const r2 = prepareRelease(
  release('2', '1', {
    declarations: v2Source,
    defaultGrants: [
      ...release('2', '1').defaultGrants,
      {
        permission: 'submission.export',
        role: 'reviewer',
        template: { key: 'all', version: 1 },
        parameters: {},
      },
    ],
    seeds: [seed('review-module', 'default-submission-site')],
  }),
);

describe('manifest reconciliation (boot sync)', () => {
  let postgres: TestPostgres;
  let registry: TenantDataSourceRegistry;
  let identity: DataSource;
  let reconciler: ManifestReconciler;
  let runner: TenantTransactionRunner;
  let admin: pg.Client;
  const passwords = new Map<string, string>();
  const password = (tenant: TenantId, purpose: ConnectionPurpose) => {
    const key = `${tenant}/${purpose}`;
    if (!passwords.has(key)) passwords.set(key, randomBytes(24).toString('base64url'));
    return passwords.get(key)!;
  };
  const as = (
    tenant: TenantId,
    purpose: ConnectionPurpose,
    database = tenantDatabaseName(tenant),
  ): Connection => ({
    ...postgres.admin,
    username: tenantRoleName(tenant, purpose),
    password: password(tenant, purpose),
    database,
  });
  const fence = async () =>
    (
      await admin.query<{ revision: string; sequence: string; hash: string }>(
        `SELECT revision::text AS revision, release_sequence::text AS sequence, encode(manifest_hash, 'hex') AS hash
         FROM authz_fence`,
      )
    ).rows[0]!;
  const count = async (sql: string, params: unknown[] = []) =>
    Number(
      (await admin.query<{ n: string }>(`SELECT count(*)::text AS n FROM ${sql}`, params)).rows[0]!
        .n,
    );
  const rejected = async (attempt: () => Promise<unknown>, reason: string) => {
    const before = await fence();
    await assert.rejects(
      attempt(),
      (error: unknown) => error instanceof ReleaseRejectedError && error.reason === reason,
    );
    assert.deepEqual(await fence(), before, 'rejected release changes nothing');
  };

  before(async () => {
    postgres = await startPostgres();
    const provisioner = new TenantProvisioner(postgres.admin, {
      identityDatabase: 'authz_identity',
    });
    await provisioner.provisionIdentity();
    for (const tenant of [tenantA, tenantB]) {
      await provisioner.provision({
        tenantId: tenant,
        displayLabel: 'Sync fixture',
        passwords: {
          data: password(tenant, 'data'),
          authority: password(tenant, 'authority'),
          sync: password(tenant, 'sync'),
        },
      });
    }
    identity = await new DataSource(
      identityDataSourceOptions({ ...postgres.admin, database: 'authz_identity' }),
    ).initialize();
    registry = new TenantDataSourceRegistry({
      host: postgres.admin.host,
      port: postgres.admin.port,
      poolSize: { data: 2, authority: 2, sync: 2 },
      maxConnections: 12,
      idleTimeoutMs: 60_000,
      resolveRoute: directoryRouteResolver(identity, (tenant, purpose) =>
        Promise.resolve({ password: password(tenant, purpose), credentialVersion: 'v1' }),
      ),
    });
    runner = new TenantTransactionRunner(registry, { deadlineMs: 10_000, lockTimeoutMs: 5_000 });
    reconciler = new ManifestReconciler(runner, { actor: deployer, capabilities });
    admin = await openClient({ ...postgres.admin, database: tenantDatabaseName(tenantA) });
  });
  after(async () => {
    await admin?.end();
    await registry?.close();
    await identity?.destroy();
    await postgres?.stop();
  });

  test('missing validator or obligation handler capability fails before any write', async () => {
    const needs = prepareRelease(
      release('1', '0', {
        declarations: {
          ...declarationsSource,
          capabilities: { validators: ['minimumAssurance@1'], obligationHandlers: [] },
        },
      }),
    );
    await rejected(() => reconciler.reconcile(tenantA, needs), 'missing_capability');
  });

  test('first sync publishes catalog, policies, templates, code roles and default grants', async () => {
    const result = await reconciler.reconcile(tenantA, r1);
    assert.equal(result.changed, true);
    assert.deepEqual(await fence(), { revision: '2', sequence: '1', hash: r1.hash });
    assert.equal(result.manifestHash, r1.hash);
    assert.equal(result.revision, '2');
    assert.equal(await count('permission_catalog'), 4);
    assert.equal(await count('permission_policy'), 2);
    assert.equal(await count('scope_template'), declarationsSource.templates.length);
    assert.equal(await count(`role_definition WHERE managed_by = 'code'`), 2);
    assert.equal(await count(`policy_rule WHERE managed_by = 'code'`), 2);
    assert.equal(
      await count('resource_relation_definition'),
      1,
      'identity-target relations are code-validated, not stored',
    );
    assert.equal(await count('audit_outbox WHERE event_kind = $1', [bytes('manifest.sync')]), 1);
  });

  test('same sequence and hash is a no-op', async () => {
    const before = await fence();
    assert.deepEqual(await reconciler.reconcile(tenantA, r1), {
      changed: false,
      revision: before.revision,
      manifestHash: r1.hash,
    });
    assert.deepEqual(await fence(), before);
    assert.equal(await count('audit_outbox WHERE event_kind = $1', [bytes('manifest.sync')]), 1);
  });

  test('same sequence with a different hash is rejected', async () => {
    const conflicting = prepareRelease(
      release('1', '0', {
        roles: [
          { key: 'reviewer', authorityLevel: 10, label: 'Renamed' },
          { key: 'manager', authorityLevel: 50, label: 'Manager' },
        ],
      }),
    );
    assert.notEqual(conflicting.hash, r1.hash);
    await rejected(() => reconciler.reconcile(tenantA, conflicting), 'conflicting_release');
  });

  test('a release whose expected predecessor is not current is rejected', async () => {
    await rejected(
      () => reconciler.reconcile(tenantA, prepareRelease(release('3', '2'))),
      'predecessor_mismatch',
    );
  });

  test('new policy version switches the binding; only new permissions get default grants; runtime rules kept', async () => {
    // Business data the seeds refer to, and tenant-owned state the sync must not touch.
    await admin.query(
      `INSERT INTO object_ref VALUES ($1, gen_random_uuid(), $2, 'integer', $3),
                                             ($1, gen_random_uuid(), $4, 'uuid', $5), ($1, gen_random_uuid(), $4, 'uuid', $6)`,
      [
        tenantA,
        bytes('submission'),
        bytes(submissionKey),
        bytes('site'),
        bytes(siteKey),
        bytes(otherSiteKey),
      ],
    );
    await admin.query(`DELETE FROM policy_rule WHERE managed_by = 'code' AND permission_key = $1`, [
      bytes('submission.read'),
    ]);
    await admin.query(
      `INSERT INTO policy_rule VALUES ($1, gen_random_uuid(), $2, NULL, $3, 'allow', $4, 1, '{"status":"x"}', 'tenant')`,
      [tenantA, bytes('submission.read'), bytes('manager'), bytes('statusIs')],
    );

    const result = await reconciler.reconcile(tenantA, r2);
    assert.equal(result.changed, true);
    const approve = await admin.query(
      `SELECT policy_version FROM permission_catalog WHERE permission_key = $1`,
      [bytes('submission.approve')],
    );
    assert.deepEqual(approve.rows, [{ policy_version: 2 }]);
    assert.equal(
      await count('permission_policy WHERE policy_key = $1', [bytes('approval')]),
      2,
      'v1 kept',
    );
    assert.equal(
      await count(`policy_rule WHERE managed_by = 'code' AND permission_key = $1`, [
        bytes('submission.export'),
      ]),
      1,
    );
    assert.equal(
      await count(`policy_rule WHERE managed_by = 'code' AND permission_key = $1`, [
        bytes('submission.read'),
      ]),
      0,
      'a code grant removed by an administrator is not resurrected for an existing permission',
    );
    assert.equal(await count(`policy_rule WHERE managed_by = 'tenant'`), 1);
    assert.equal(await count('relation_edge WHERE seed_owner = $1', [bytes('review-module')]), 1);
    assert.deepEqual(await fence(), { revision: '3', sequence: '2', hash: r2.hash });
  });

  test('an older release never downgrades', async () => {
    await rejected(() => reconciler.reconcile(tenantA, r1), 'downgrade');
  });

  test('a seed colliding with a runtime tuple rolls back the whole release', async () => {
    await admin.query(
      `INSERT INTO relation_edge (tenant_id, relation_key, relation_version, source_object, source_type, target_object, target_type, starts_at)
       SELECT $1, $2, 1, s.object_id, $3, t.object_id, $4, '2020-01-01Z'
       FROM object_ref s, object_ref t WHERE s.key_bytes = $5 AND t.key_bytes = $6`,
      [
        tenantA,
        bytes('submission.site'),
        bytes('submission'),
        bytes('site'),
        bytes(submissionKey),
        bytes(otherSiteKey),
      ],
    );
    const r3 = prepareRelease(
      release('3', '2', {
        declarations: {
          ...v2Source,
          templates: [
            ...v2Source.templates,
            {
              key: 'brandNew',
              version: 1,
              resource: 'site',
              parameters: {},
              expression: { op: 'constant', value: true },
            },
          ],
        },
        seeds: [
          seed('review-module', 'default-submission-site'),
          seed('review-module', 'second', otherSiteKey),
        ],
      }),
    );
    await rejected(() => reconciler.reconcile(tenantA, r3), 'collision');
    assert.equal(
      await count('relation_edge WHERE seed_owner IS NULL'),
      1,
      'runtime tuple untouched',
    );
    assert.equal(
      await count('scope_template WHERE template_key = $1', [bytes('brandNew')]),
      0,
      'nothing partially applied',
    );
  });

  test("a seed colliding with another owner's seed rolls back", async () => {
    const r3 = prepareRelease(
      release('3', '2', {
        declarations: v2Source,
        seeds: [
          seed('review-module', 'default-submission-site'),
          seed('other-module', 'same-edge'),
        ],
      }),
    );
    await rejected(() => reconciler.reconcile(tenantA, r3), 'collision');
  });

  test('a seed referencing a missing object rolls back', async () => {
    const r3 = prepareRelease(
      release('3', '2', {
        declarations: v2Source,
        seeds: [
          seed('review-module', 'default-submission-site'),
          seed('review-module', 'ghost', '00000000-0000-4000-8000-00000000dead'),
        ],
      }),
    );
    await rejected(() => reconciler.reconcile(tenantA, r3), 'missing_reference');
  });

  test('a missing code seed fails readiness even when the hash matches', async () => {
    await admin.query('DELETE FROM relation_edge WHERE seed_owner = $1', [bytes('review-module')]);
    await assert.rejects(
      reconciler.reconcile(tenantA, r2),
      (e: unknown) => e instanceof ReleaseRejectedError && e.reason === 'not_ready',
    );
    await admin.query(
      `INSERT INTO relation_edge SELECT $1, $2, 1, s.object_id, $3, t.object_id, $4, '2026-10-12Z', NULL, $5, $6
       FROM object_ref s, object_ref t WHERE s.key_bytes = $7 AND t.key_bytes = $8`,
      [
        tenantA,
        bytes('submission.site'),
        bytes('submission'),
        bytes('site'),
        bytes('review-module'),
        bytes('default-submission-site'),
        bytes(submissionKey),
        bytes(siteKey),
      ],
    );
    assert.equal((await reconciler.reconcile(tenantA, r2)).changed, false);
  });

  test('seeds are removed only by an explicit removal from the same owner', async () => {
    const base = { declarations: v2Source, defaultGrants: r2.defaultGrants.map((g) => ({ ...g })) };
    await reconciler.reconcile(tenantA, prepareRelease(release('3', '2', { ...base, seeds: [] })));
    assert.equal(
      await count('relation_edge WHERE seed_owner IS NOT NULL'),
      1,
      'omitted seed is kept',
    );
    await reconciler.reconcile(
      tenantA,
      prepareRelease(
        release('4', '3', {
          ...base,
          removeSeeds: [{ owner: 'other-module', key: 'default-submission-site' }],
        }),
      ),
    );
    assert.equal(
      await count('relation_edge WHERE seed_owner IS NOT NULL'),
      1,
      'other owner cannot remove it',
    );
    await reconciler.reconcile(
      tenantA,
      prepareRelease(
        release('5', '4', {
          ...base,
          removeSeeds: [{ owner: 'review-module', key: 'default-submission-site' }],
        }),
      ),
    );
    assert.equal(await count('relation_edge WHERE seed_owner IS NOT NULL'), 0);
  });

  test('two instances booting together publish exactly one revision', async () => {
    const before = await fence();
    const r6 = prepareRelease(
      release('6', '5', {
        declarations: v2Source,
        defaultGrants: r2.defaultGrants.map((g) => ({ ...g })),
      }),
    );
    const second = new ManifestReconciler(
      new TenantTransactionRunner(registry, { deadlineMs: 10_000, lockTimeoutMs: 5_000 }),
      {
        actor: deployer,
        capabilities,
      },
    );
    const results = await Promise.all([
      reconciler.reconcile(tenantA, r6),
      second.reconcile(tenantA, r6),
    ]);
    assert.deepEqual(results.map((r) => r.changed).sort(), [false, true]);
    assert.equal(BigInt((await fence()).revision), BigInt(before.revision) + 1n);
  });

  test('sync credential privilege matrix', async () => {
    await withClient(as(tenantA, 'sync'), async (c) => {
      await c.query('BEGIN');
      await c.query('SELECT revision FROM authz_fence FOR UPDATE');
      await c.query(`UPDATE permission_policy SET lifecycle = lifecycle`);
      await c.query('ROLLBACK');
      for (const statement of [
        `UPDATE permission_policy SET definition = '{}'`,
        'DELETE FROM permission_policy',
        'SELECT * FROM membership',
        'SELECT * FROM member_role',
        'SELECT * FROM record_exception',
        'SELECT * FROM identity_relation',
        'UPDATE tenant_anchor SET tenant_id = tenant_id',
        `UPDATE role_definition SET managed_by = 'tenant'`,
        'DELETE FROM policy_rule',
        `UPDATE policy_rule SET effect = 'allow'`,
        'CREATE TABLE sync_escape (id int)',
        `SELECT public.authz_acquire_shared_fence('${tenantA}')`,
      ]) {
        assert.equal(await sqlState(c.query(statement)), '42501', statement);
      }
    });
    assert.equal(
      await sqlState(
        withClient(as(tenantA, 'sync', tenantDatabaseName(tenantB)), () => Promise.resolve()),
      ),
      '42501',
    );
  });
});
