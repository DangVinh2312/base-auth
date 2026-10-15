// Frozen copy of 50d6053 (release 1 write path) for upgrade tests; do not edit beyond imports.
import type { SystemDeclarations } from '@base-authorization/core';
import type { ProductReleaseSource } from './product-manifest.ts';
import type { ProductStorageBindings } from '@base-authorization/typeorm-postgres';

/** Account administration fragment: data only, composed into the release in authorization/. */
export const accountDeclarations: Pick<
  SystemDeclarations,
  'resources' | 'policies' | 'templates' | 'boundaries'
> = {
  resources: [
    {
      key: 'account',
      keyKind: 'uuid',
      fields: { state: { kind: 'string' }, authorityLevel: { kind: 'integer' } },
      actions: {
        suspend: { policy: { key: 'freshAuthentication', version: 1 }, boundary: 'required' },
      },
    },
  ],
  policies: [
    {
      key: 'freshAuthentication',
      version: 1,
      contextRequirements: [{ validator: 'fresh@1', parameters: {} }],
      requiredScope: { op: 'constant', value: true },
      obligations: [{ handler: 'audit@1' }],
    },
  ],
  templates: [
    {
      key: 'allAccounts',
      version: 1,
      resource: 'account',
      parameters: {},
      expression: { op: 'constant', value: true },
    },
  ],
  boundaries: [
    {
      key: 'rootAccounts',
      version: 1,
      entries: [
        {
          permission: 'account.suspend',
          contextRequirements: [],
          requiredScope: {
            op: 'lte',
            field: 'authorityLevel',
            value: { from: 'literal', value: '999' },
          },
        },
      ],
    },
  ],
};

export const accountSystemGrants: ProductReleaseSource['systemGrants'] = [
  {
    owner: 'product',
    key: 'root-suspend',
    role: 'system.root',
    permission: 'account.suspend',
    template: { key: 'allAccounts', version: 1 },
    parameters: {},
  },
];

export const accountBinding: ProductStorageBindings['resources'][number] = {
  resource: 'account',
  // Effective rank (column or assigned roles), never the raw column alone.
  table: 'account_rank',
  objectIdColumn: 'id',
  keyColumn: 'id',
  columns: { state: 'state', authorityLevel: 'authority_level' },
  projection: ['state', 'authorityLevel'],
};
