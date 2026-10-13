// Provisions the identity database or one tenant (database, login roles, grants, anchor, fence,
// directory route). Idempotent: re-run with the same --id to resume after a failure.
// Usage:
//   pnpm run db:provision -- identity
//   pnpm run db:provision -- tenant --label "Tenant A" [--id <uuid>]
// Tenant passwords come from TENANT_DATA_PASSWORD / TENANT_AUTHORITY_PASSWORD / TENANT_SYNC_PASSWORD
// and are never printed.
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { parseTenantId } from '@base-authorization/core';
import { TenantProvisioner } from '@base-authorization/typeorm-postgres';
import { adminConnection, identityDatabaseName, requireEnv } from './env.ts';

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: { id: { type: 'string' }, label: { type: 'string' } },
  args: process.argv.slice(2).filter((arg) => arg !== '--'),
});
const provisioner = new TenantProvisioner(adminConnection(), {
  identityDatabase: identityDatabaseName(),
});

switch (positionals[0]) {
  case 'identity': {
    const applied = await provisioner.provisionIdentity();
    console.log(`identity database ready (${applied.length} migration(s) applied)`);
    break;
  }
  case 'tenant': {
    if (!values.label) throw new Error('--label is required');
    const tenantId = parseTenantId(values.id ?? randomUUID());
    console.log(`provisioning tenant ${tenantId} (re-run with --id ${tenantId} to resume)`);
    await provisioner.provision({
      tenantId,
      displayLabel: values.label,
      passwords: {
        data: requireEnv('TENANT_DATA_PASSWORD'),
        authority: requireEnv('TENANT_AUTHORITY_PASSWORD'),
        sync: requireEnv('TENANT_SYNC_PASSWORD'),
      },
    });
    console.log(`tenant ${tenantId} provisioned and routable`);
    break;
  }
  default:
    throw new Error('Usage: db:provision -- identity | tenant --label <label> [--id <uuid>]');
}
