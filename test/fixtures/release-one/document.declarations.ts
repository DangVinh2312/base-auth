// Frozen copy of 50d6053 (release 1 write path) for upgrade tests; do not edit beyond imports.
import type { SystemDeclarations } from '@base-authorization/core';
import type { ProductReleaseSource } from './product-manifest.ts';
import type { ProductStorageBindings } from '@base-authorization/typeorm-postgres';

/** Document capability fragment: data only, composed into the release in authorization/. */
export const documentDeclarations: Pick<
  SystemDeclarations,
  'resources' | 'policies' | 'templates' | 'boundaries'
> = {
  resources: [
    {
      key: 'document',
      keyKind: 'uuid',
      fields: { title: { kind: 'string' }, ownerId: { kind: 'uuid' }, state: { kind: 'string' } },
      actions: {
        read: { policy: { key: 'readable', version: 1 }, boundary: 'optional' },
        update: { policy: { key: 'editable', version: 1 }, boundary: 'optional' },
      },
    },
  ],
  policies: [
    {
      key: 'readable',
      version: 1,
      contextRequirements: [],
      requiredScope: { op: 'constant', value: true },
      obligations: [],
    },
    {
      key: 'editable',
      version: 1,
      contextRequirements: [],
      requiredScope: { op: 'eq', field: 'state', value: { from: 'literal', value: 'draft' } },
      obligations: [{ handler: 'audit@1' }],
    },
  ],
  templates: [
    {
      key: 'ownedDocuments',
      version: 1,
      resource: 'document',
      parameters: {},
      expression: { op: 'eq', field: 'ownerId', value: { from: 'principal', name: 'id' } },
    },
  ],
  boundaries: [],
};
export const documentDefaultGrants: ProductReleaseSource['defaultGrants'] = [
  {
    permission: 'document.read',
    role: 'reviewer',
    template: { key: 'ownedDocuments', version: 1 },
    parameters: {},
  },
];
export const documentBinding: ProductStorageBindings['resources'][number] = {
  resource: 'document',
  table: 'document',
  objectIdColumn: 'object_id',
  keyColumn: 'id',
  columns: { title: 'title', ownerId: 'owner_id', state: 'state' },
  projection: ['title', 'state'],
};
