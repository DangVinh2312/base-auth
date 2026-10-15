import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import { type ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductTransactionRunner,
  ProductManifestReconciler,
  prepareProductRelease,
  ProductIdentityService,
  createProductPasswordHasher,
} from '@base-authorization/typeorm-postgres/composition';
import {
  provisionProductDatabase,
  productDataSourceOptions,
  bootstrapProductRoot,
  reissueRootActivation,
} from '@base-authorization/typeorm-postgres/operations';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';
import { productDeclarations } from '../apps/api/dist/authorization/product.manifest.js';
import { core } from '../packages/core/test/fixtures.ts';

let fixture: TestPostgres;
let fixtureNumber = 0;
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
    p,
    randomBytes(24).toString('hex'),
  ]),
) as Record<ProductDatabasePurpose, string>;
const actor = randomUUID() as IdentityId;
const base = {
  sequence: '1',
  predecessor: '0',
  declarations: productDeclarations,
  roles: [{ key: 'reviewer', label: 'Reviewer' }],
  defaultGrants: [
    {
      permission: 'document.read',
      role: 'reviewer',
      template: { key: 'ownedDocuments', version: 1 },
      parameters: {},
    },
  ],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};
before(async () => {
  fixture = await startPostgres();
});
after(async () => {
  await fixture?.stop();
});

async function withProduct(
  run: (
    reconciler: ProductManifestReconciler,
    migration: DataSource,
    settings: Awaited<ReturnType<typeof provisionProductDatabase>>,
  ) => Promise<void>,
): Promise<void> {
  const database = `system_regression_${++fixtureNumber}`;
  await withClient(fixture.superuser, (c) => c.query(`CREATE DATABASE ${database}`));
  const settings = await provisionProductDatabase({ ...fixture.superuser, database }, passwords);
  const sync = await new DataSource(productDataSourceOptions(settings.sync)).initialize();
  const migration = await new DataSource(productDataSourceOptions(settings.migration)).initialize();
  try {
    const reconciler = new ProductManifestReconciler(new ProductTransactionRunner({ sync }), {
      core,
      actor,
      capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
    });
    await reconciler.reconcile(prepareProductRelease(base, core));
    await run(reconciler, migration, settings);
  } finally {
    await migration.destroy();
    await sync.destroy();
  }
}

async function offlineAlter(
  migration: DataSource,
  sql: string,
  parameters: unknown[] = [],
): Promise<void> {
  await migration.query('ALTER TABLE policy_rule DISABLE TRIGGER protect_product_rows');
  try {
    await migration.query(sql, parameters);
  } finally {
    await migration.query('ALTER TABLE policy_rule ENABLE TRIGGER protect_product_rows');
  }
}

test('a new release cannot adopt drift in a persisted code-owned grant omitted from it', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(migration, "UPDATE policy_rule SET effect='deny' WHERE managed_by='code'");
    await assert.rejects(
      reconciler.reconcile(prepareProductRelease(base, core)),
      /drift|not_ready|immutable_definition/,
    );
    const next = prepareProductRelease(
      { ...base, sequence: '2', predecessor: '1', defaultGrants: [] },
      core,
    );
    await assert.rejects(reconciler.reconcile(next), /drift|not_ready|immutable_definition/);
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});
test('a code-owned grant with a rewritten rule ID is drift, not a fresh grant', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(migration, "UPDATE policy_rule SET rule_id=$1 WHERE managed_by='code'", [
      randomUUID(),
    ]);
    const next = prepareProductRelease({ ...base, sequence: '2', predecessor: '1' }, core);
    await assert.rejects(
      reconciler.reconcile(next),
      /drift|not_ready|collision|immutable_definition/,
    );
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});

test('OIDC Root bootstrap issues a one-time OIDC proof only for one exact pre-bound subject', async () => {
  await withProduct(async (_reconciler, migration, settings) => {
    const bootstrap = await new DataSource(
      productDataSourceOptions(settings.bootstrap),
    ).initialize();
    try {
      const runner = new ProductTransactionRunner({ bootstrap });
      const target = randomUUID() as IdentityId;
      await migration.query(`INSERT INTO app_user(id,state) VALUES($1,'pending')`, [target]);
      await migration.query(
        `INSERT INTO external_identity(issuer,subject,user_id) VALUES('https://idp.example.test','root-subject',$1),('https://other.example.test','second',$1)`,
        [target],
      );
      const input = {
        operationId: randomUUID(),
        userId: target,
        method: 'oidc' as const,
        issuer: 'https://idp.example.test',
        subject: 'root-subject',
      };
      // A second enabled binding would let another subject finish the activation.
      await assert.rejects(
        bootstrapProductRoot(runner, prepareProductRelease(base, core), input),
        /OIDC binding/,
      );
      await migration.query(`DELETE FROM external_identity WHERE subject='second'`);
      const result = await bootstrapProductRoot(runner, prepareProductRelease(base, core), input);
      assert.match(result.activationSecret ?? '', /^[A-Za-z0-9_-]{43}$/);
      assert.deepEqual(
        await migration.query('SELECT purpose FROM one_time_token WHERE user_id=$1', [target]),
        [{ purpose: 'oidc-activation' }],
      );
      // Reissue re-confirms the exact binding and the method.
      const userId = target;
      for (const wrong of [
        { method: 'oidc' as const },
        { method: 'oidc' as const, issuer: 'https://idp.example.test' },
        { method: 'oidc' as const, issuer: 'https://idp.example.test', subject: 'other' },
        { method: 'oidc' as const, issuer: 'https://other.example.test', subject: 'root-subject' },
        { method: 'local' as const },
      ])
        await assert.rejects(
          reissueRootActivation(runner, { userId, ...wrong }, core),
          /OIDC binding|method/,
        );
      const reissued = await reissueRootActivation(
        runner,
        {
          userId,
          method: 'oidc',
          issuer: 'https://idp.example.test',
          subject: 'root-subject',
        },
        core,
      );
      assert.notEqual(reissued.activationSecret, result.activationSecret);
    } finally {
      await bootstrap.destroy();
    }
  });
});

test('a Root promotion commits only with the marker naming it', async () => {
  await withProduct(async (_reconciler, migration, settings) => {
    const bootstrap = await new DataSource(
      productDataSourceOptions(settings.bootstrap),
    ).initialize();
    try {
      const runner = new ProductTransactionRunner({ bootstrap });

      const denied = (e: { code?: string; driverError?: { code?: string } }) =>
        (e.driverError?.code ?? e.code) === '42501';

      const target = randomUUID();
      const other = randomUUID();
      await migration.query(`INSERT INTO app_user(id,state) VALUES($1,'pending'),($2,'pending')`, [
        target,
        other,
      ]);
      const promote = `UPDATE app_user SET kind='root' WHERE id=$1`;
      // No marker at all: the deferred check refuses the commit.
      await assert.rejects(
        runner.run('bootstrap', (tx) => tx.manager.query(promote, [target])),
        denied,
      );
      // A marker naming somebody else, and forcing the check early, are refused too.
      await assert.rejects(
        runner.run('bootstrap', async (tx) => {
          await tx.manager.query(promote, [target]);
          await tx.manager.query(
            'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
            [randomUUID(), other],
          );
        }),
        denied,
      );
      await assert.rejects(
        runner.run('bootstrap', async (tx) => {
          await tx.manager.query('SET CONSTRAINTS ALL IMMEDIATE');
          await tx.manager.query(promote, [target]);
        }),
        denied,
      );
      assert.deepEqual(await migration.query(`SELECT id FROM app_user WHERE kind='root'`), []);
      assert.deepEqual(
        await migration.query('SELECT initialized_at FROM security_bootstrap_state'),
        [{ initialized_at: null }],
      );
    } finally {
      await bootstrap.destroy();
    }
  });
});

test('only the bootstrap credential issues activation for Root', async () => {
  await withProduct(async (_reconciler, migration, settings) => {
    const bootstrap = await new DataSource(
      productDataSourceOptions(settings.bootstrap),
    ).initialize();
    const identityPool = await new DataSource(
      productDataSourceOptions(settings.identity),
    ).initialize();
    try {
      const runner = new ProductTransactionRunner({ bootstrap, identity: identityPool });
      const identity = new ProductIdentityService(
        runner,
        await createProductPasswordHasher(new Set()),
      );
      const release = prepareProductRelease(base, core);

      const bootstrapInput = (userId: string) => ({
        operationId: randomUUID(),
        userId: userId as IdentityId,
        method: 'local' as const,
      });

      const denied = (e: { code?: string; driverError?: { code?: string } }) =>
        (e.driverError?.code ?? e.code) === '42501';

      // An identity invitation issued before bootstrap cannot later activate Root.
      const invited = randomUUID();
      await migration.query(
        `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'invited@example.test','pending')`,
        [invited],
      );
      await runner.run('revoke', (tx) => identity.issueActivation(tx, invited));
      await assert.rejects(bootstrapProductRoot(runner, release, bootstrapInput(invited)), denied);
      // After bootstrap, identity cannot mint another proof for the pending Root.
      const root = randomUUID();
      await migration.query(
        `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'root@example.test','pending')`,
        [root],
      );
      assert.ok((await bootstrapProductRoot(runner, release, bootstrapInput(root))).initialized);
      await assert.rejects(
        runner.run('revoke', (tx) => identity.issueActivation(tx, root)),
        denied,
      );
      await assert.rejects(
        identityPool.query(
          `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES(sha256('raw'::bytea),$1,'oidc-activation',statement_timestamp()+interval '1 minute')`,
          [root],
        ),
        denied,
      );
      // Nor retarget the earlier ordinary invitation: identity may only mark tokens consumed.
      await assert.rejects(
        identityPool.query('UPDATE one_time_token SET user_id=$1 WHERE user_id=$2', [
          root,
          invited,
        ]),
        denied,
      );
      // The bootstrap credential reissues a lost or expired proof for the pending Root only.
      await assert.rejects(
        reissueRootActivation(runner, { userId: invited as IdentityId, method: 'local' }, core),
        /pending bootstrap Root/,
      );
      const { activationSecret } = await reissueRootActivation(
        runner,
        {
          userId: root as IdentityId,
          method: 'local',
        },
        core,
      );
      assert.deepEqual(
        await migration.query(
          'SELECT count(*)::int n FROM one_time_token WHERE user_id=$1 AND consumed_at IS NULL',
          [root],
        ),
        [{ n: 1 }],
      );
      // The voided proof stays void: no login revives, deletes or rewrites a token.
      for (const pool of [identityPool, bootstrap])
        await assert.rejects(
          pool.query('UPDATE one_time_token SET consumed_at=NULL WHERE user_id=$1', [root]),
          denied,
        );
      await assert.rejects(
        identityPool.query('DELETE FROM one_time_token WHERE user_id=$1', [root]),
        denied,
      );
      await identity.activate(activationSecret, 'a long unique reissued root password', 'reissue');
      await assert.rejects(
        reissueRootActivation(runner, { userId: root as IdentityId, method: 'local' }, core),
        /pending bootstrap Root/,
      );
    } finally {
      await identityPool.destroy();
      await bootstrap.destroy();
    }
  });
});
