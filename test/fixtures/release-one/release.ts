// Release 1 exactly as 50d6053 published it (apps/api/src/authorization/product-manifest.ts).
import type { AuthorizationCore, SystemDeclarations } from '@base-authorization/core';
import {
  prepareProductRelease,
  type ProductReleaseManifest,
  type ProductReleaseSource,
} from './product-manifest.ts';
import { accountDeclarations, accountSystemGrants } from './account.declarations.ts';
import { documentDeclarations, documentDefaultGrants } from './document.declarations.ts';

const fragments = [documentDeclarations, accountDeclarations];
const releaseOneDeclarations: SystemDeclarations = {
  capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  resources: fragments.flatMap((f) => f.resources),
  policies: fragments.flatMap((f) => f.policies),
  templates: fragments.flatMap((f) => f.templates),
  boundaries: fragments.flatMap((f) => f.boundaries),
  relations: [],
};
export const releaseOneSource: ProductReleaseSource = {
  sequence: '1',
  predecessor: '0',
  declarations: releaseOneDeclarations,
  roles: [
    { key: 'system.root', label: 'Root', authorityLevel: 1000 },
    { key: 'reviewer', label: 'Reviewer', authorityLevel: 10 },
  ],
  defaultGrants: documentDefaultGrants,
  systemGrants: accountSystemGrants,
  removeSystemGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};

export function prepareReleaseOne(
  core: AuthorizationCore,
  source: ProductReleaseSource = releaseOneSource,
): ProductReleaseManifest {
  return prepareProductRelease(source, core);
}
