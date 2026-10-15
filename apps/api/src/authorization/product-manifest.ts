import {
  type AuthorizationCore,
  createAuthorizationCore,
  type SystemDeclarations,
} from '@base-authorization/core';
import {
  type ProductReleaseManifest,
  type ProductReleaseSource,
  type ProductStorageBindings,
} from '@base-authorization/typeorm-postgres';
import { prepareProductRelease } from '@base-authorization/typeorm-postgres/composition';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';
import { accountBinding, accountDeclarations } from '../administration/account.declarations.js';
import {
  documentBinding,
  documentDeclarations,
  documentDefaultGrants,
} from '../documents/document.declarations.js';

/**
 * Value codec selection for this product: the API runtime and the offline CLI (tools/product.ts)
 * both call this, so boot validation, sync and request evaluation share one set of semantics.
 */
export function createProductAuthorizationCore(): AuthorizationCore {
  return createAuthorizationCore({
    values: createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
  });
}

// Fragment order is part of the declarations; keep it stable.
const fragments = [documentDeclarations, accountDeclarations];
export const productDeclarations: SystemDeclarations = {
  capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  resources: fragments.flatMap((f) => f.resources),
  policies: fragments.flatMap((f) => f.policies),
  templates: fragments.flatMap((f) => f.templates),
  boundaries: fragments.flatMap((f) => f.boundaries),
  relations: [],
};

/** Release content is data only; codecs are provenance and never enter the manifest hash. */
export const productReleaseSource: ProductReleaseSource = {
  // Release 2 (ADR 0012): Root left IAM; no system role, system grant or rank boundary remains.
  sequence: '2',
  predecessor: '1',
  declarations: productDeclarations,
  roles: [{ key: 'reviewer', label: 'Reviewer' }],
  defaultGrants: documentDefaultGrants,
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};

export function createProductRelease(core: AuthorizationCore): ProductReleaseManifest {
  return prepareProductRelease(productReleaseSource, core);
}

export const productBindings: ProductStorageBindings = {
  resources: [documentBinding, accountBinding],
  domains: {},
};
