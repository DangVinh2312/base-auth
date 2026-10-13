import type { SystemDeclarations } from '@base-authorization/core';
import {
  prepareProductRelease,
  type ProductStorageBindings,
} from '@base-authorization/typeorm-postgres';
export const productDeclarations: SystemDeclarations = {
  capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
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
      key: 'ownedDocuments',
      version: 1,
      resource: 'document',
      parameters: {},
      expression: { op: 'eq', field: 'ownerId', value: { from: 'principal', name: 'id' } },
    },
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
  relations: [],
};
export const productRelease = prepareProductRelease({
  sequence: '1',
  predecessor: '0',
  declarations: productDeclarations,
  roles: [
    { key: 'system.root', label: 'Root', authorityLevel: 1000 },
    { key: 'reviewer', label: 'Reviewer', authorityLevel: 10 },
  ],
  defaultGrants: [
    {
      permission: 'document.read',
      role: 'reviewer',
      template: { key: 'ownedDocuments', version: 1 },
      parameters: {},
    },
  ],
  systemGrants: [
    {
      owner: 'product',
      key: 'root-suspend',
      role: 'system.root',
      permission: 'account.suspend',
      template: { key: 'allAccounts', version: 1 },
      parameters: {},
    },
  ],
  removeSystemGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
});
export const productBindings: ProductStorageBindings = {
  resources: [
    {
      resource: 'document',
      table: 'document',
      objectIdColumn: 'object_id',
      keyColumn: 'id',
      columns: { title: 'title', ownerId: 'owner_id', state: 'state' },
      projection: ['title', 'state'],
    },
    {
      resource: 'account',
      table: 'app_user',
      objectIdColumn: 'id',
      keyColumn: 'id',
      columns: { state: 'state', authorityLevel: 'authority_level' },
      projection: ['state', 'authorityLevel'],
    },
  ],
  domains: {},
};
