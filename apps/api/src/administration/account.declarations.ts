import type { SystemDeclarations } from '../authorization/core/authorization.declarations.js';
import type { ProductStorageBindings } from '../authorization/product-sql.compiler.js';

/** Account administration fragment: data only, composed into the release in authorization/. */
export const accountDeclarations: Pick<
  SystemDeclarations,
  'resources' | 'policies' | 'templates' | 'boundaries'
> = {
  resources: [
    {
      key: 'account',
      keyKind: 'uuid',
      fields: { state: { kind: 'string' } },
      actions: {
        // An IAM principal needs a grant and an explicit boundary; Root bypasses both (ADR 0012).
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
  boundaries: [],
};

export const accountBinding: ProductStorageBindings['resources'][number] = {
  resource: 'account',
  // IAM accounts only: Root and absent ids look the same to every account action.
  table: 'iam_account',
  objectIdColumn: 'id',
  keyColumn: 'id',
  columns: { state: 'state' },
  projection: ['state'],
};
