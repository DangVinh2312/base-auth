import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { DataSource } from 'typeorm';
import { ProductBindingRegistry } from '../apps/api/dist/authorization/product-sql.compiler.js';
import { ProductDataGateway } from '../apps/api/dist/authorization/product-data.gateway.js';
import { ProductTransactionRunner } from '../apps/api/dist/database/product-transaction.runner.js';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '../apps/api/dist/database/helpers/product-database.helper.js';
import { alice, input, rule, snapshot, validated, core } from './core/fixtures.ts';
import { startPostgres, withClient } from './setup-postgres.ts';

const { planUser } = core;

test('identity edges cannot grant through a business row pointing at another registered resource type', async () => {
  const postgres = await startPostgres();
  const pools = {} as Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
  try {
    const passwords = Object.fromEntries(
      ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map(
        (purpose) => [purpose, randomBytes(20).toString('hex')],
      ),
    ) as Record<
      'data' | 'identity' | 'authority' | 'sync' | 'bootstrap' | 'migration' | 'outbox',
      string
    >;
    const connections = await provisionProductDatabase(postgres.superuser, passwords);
    for (const purpose of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
      pools[purpose] = await new DataSource(
        productDataSourceOptions(connections[purpose]),
      ).initialize();
    const runner = new ProductTransactionRunner(pools);
    await pools.identity.query("INSERT INTO app_user(id,state) VALUES($1,'active')", [alice]);
    for (const [type, kind] of [
      ['submission', 'integer'],
      ['site', 'uuid'],
    ] as const)
      await pools.sync.query(
        'INSERT INTO resource_type(type_key,key_kind,binding_key) VALUES($1,$2,$1)',
        [Buffer.from(type), kind],
      );
    const wrongObject = randomUUID();
    const rightObject = randomUUID();
    await runner.run('admin', async (tx) => {
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3),($4,$5,'integer',$6)",
        [
          wrongObject,
          Buffer.from('site'),
          Buffer.from(randomUUID()),
          rightObject,
          Buffer.from('submission'),
          Buffer.from('2'),
        ],
      );
      for (const object of [wrongObject, rightObject])
        await tx.manager.query(
          "INSERT INTO user_relation(relation_key,relation_version,object_id,user_id,starts_at) VALUES($1,1,$2,$3,statement_timestamp()-interval '1 minute')",
          [Buffer.from('submission.assignee'), object, alice],
        );
    });
    await withClient(postgres.superuser, async (client) => {
      await client.query(
        'CREATE TABLE submission(id bigint PRIMARY KEY,object_id uuid UNIQUE NOT NULL REFERENCES object_ref(object_id),status text,amount numeric,title text,priority bigint)',
      );
      await client.query(
        "INSERT INTO submission VALUES(1,$1,'pending',10,'wrong type',NULL),(2,$2,'pending',10,'right type',NULL)",
        [wrongObject, rightObject],
      );
      await client.query('GRANT SELECT ON submission TO product_data');
    });
    const declarations = validated();
    const bindings = new ProductBindingRegistry(core, declarations, {
      resources: [
        {
          resource: 'submission',
          table: 'submission',
          objectIdColumn: 'object_id',
          keyColumn: 'id',
          columns: { status: 'status', amount: 'amount', title: 'title', priority: 'priority' },
          projection: ['title'],
        },
        {
          resource: 'site',
          table: 'site',
          objectIdColumn: 'object_id',
          keyColumn: 'id',
          columns: { name: 'name' },
          projection: ['name'],
        },
      ],
      domains: {
        siteManagers: { table: 'site_manager', sourceColumn: 'site_id', targetColumn: 'user_id' },
      },
    });
    await runner.run('read', async (tx) => {
      const authority = snapshot({ declarations, revision: tx.revision });
      const decision = planUser(
        {
          ...input(),
          now: new Date().toISOString(),
          validUntil: new Date(Date.now() + 1500).toISOString(),
        },
        {
          ...authority,
          rules: [
            rule(
              'submission.read',
              { kind: 'identity', identity: alice },
              'allow',
              'assignedToMe@1',
            ),
          ],
        },
      );
      assert.equal(decision.effect, 'allow');
      const page = await new ProductDataGateway(bindings).list(decision.plan, {}, tx);
      assert.deepEqual(
        page.items.map((row) => row.key),
        ['2'],
      );
    });
  } finally {
    for (const pool of Object.values(pools)) await pool.destroy();
    await postgres.stop();
  }
});
