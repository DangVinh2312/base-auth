import { DataSource, type DataSourceOptions } from 'typeorm';

/** Applies pending migrations with a short-lived DataSource; returns the names applied (empty = no-op). */
export async function runMigrations(options: DataSourceOptions): Promise<string[]> {
  const dataSource = await new DataSource(options).initialize();
  try {
    const applied = await dataSource.runMigrations({ transaction: 'each' });
    return applied.map((migration) => migration.name);
  } finally {
    await dataSource.destroy();
  }
}
