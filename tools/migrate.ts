// Applies schema migrations to the identity database and every directory tenant, then re-applies
// the tenant privilege matrix. Runs with the admin credential, independent of the API.
// Usage: pnpm run db:migrate
import { TenantProvisioner } from '@base-authorization/typeorm-postgres/legacy';
import { adminConnection, identityDatabaseName } from './env.ts';

const provisioner = new TenantProvisioner(adminConnection(), {
  identityDatabase: identityDatabaseName(),
});
for (const result of await provisioner.migrateAll()) {
  console.log(`${result.database}: applied ${result.applied.length} migration(s)`);
}
