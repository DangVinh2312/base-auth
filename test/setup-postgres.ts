import { randomBytes } from 'node:crypto';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import pg from 'pg';

/** Pinned image; bump deliberately together with compose.yaml. */
export const postgresImage = 'postgres:18.4';

export interface Connection {
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
}

export interface TestPostgres {
  /** Non-superuser provisioning principal (LOGIN CREATEDB CREATEROLE), like production. */
  admin: Connection;
  superuser: Connection;

  stop(): Promise<void>;
}

/** Starts a disposable PostgreSQL 18 container with synthetic credentials only. */
export async function startPostgres(): Promise<TestPostgres> {
  const superPassword = randomBytes(18).toString('hex');
  const container = await new PostgreSqlContainer(postgresImage)
    .withDatabase('postgres')
    .withUsername('fixture_superuser')
    .withPassword(superPassword)
    .start();
  const superuser: Connection = {
    host: container.getHost(),
    port: container.getPort(),
    username: 'fixture_superuser',
    password: superPassword,
    database: 'postgres',
  };
  const adminPassword = randomBytes(18).toString('hex');
  await withClient(superuser, (client) =>
    client.query(
      `CREATE ROLE authz_provisioner LOGIN CREATEDB CREATEROLE PASSWORD '${adminPassword}'`,
    ),
  );
  return {
    superuser,
    admin: { ...superuser, username: 'authz_provisioner', password: adminPassword },

    stop: async () => {
      await container.stop();
    },
  };
}

export async function openClient(connection: Connection): Promise<pg.Client> {
  const client = new pg.Client({
    host: connection.host,
    port: connection.port,
    user: connection.username,
    password: connection.password,
    database: connection.database,
  });
  await client.connect();
  return client;
}

export async function withClient<T>(
  connection: Connection,
  run: (client: pg.Client) => Promise<T>,
): Promise<T> {
  const client = await openClient(connection);
  try {
    return await run(client);
  } finally {
    await client.end();
  }
}

/** Resolves to the PostgreSQL SQLSTATE of a rejected operation; fails if it succeeds. */
export async function sqlState(operation: Promise<unknown>): Promise<string> {
  try {
    await operation;
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string') return code;
    throw error;
  }
  throw new Error('Expected the operation to be rejected by PostgreSQL');
}
