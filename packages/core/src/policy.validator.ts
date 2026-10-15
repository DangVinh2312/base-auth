import type {
  DeclarationLimits,
  PermissionBoundary,
  PermissionPolicy,
  RelationDeclaration,
  ResourceDeclaration,
  SystemDeclarations,
  ValidatedDeclarations,
  ValidationResult,
} from './authorization.declarations.js';
import { refKey } from './authorization.declarations.js';
import {
  checkExpr,
  deepFreeze,
  type DeclarationTables,
  isFieldKind,
  MAX_PATH_DEPTH,
  type Normalize,
} from './expression.helper.js';

const identifier = /^[a-z][A-Za-z0-9_]*$/;
const dottedKey = /^[a-z][A-Za-z0-9_]*(\.[a-z][A-Za-z0-9_]*)*$/;
const handlerName = /^[A-Za-z][A-Za-z0-9_.-]*@[1-9][0-9]*$/;
const keyKinds = ['integer', 'uuid', 'string'];
const lifecycles = ['active', 'deprecated', 'retired'];
const boundaryRequirements = ['required', 'optional'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isVersion = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const isScalar = (value: unknown) => typeof value === 'string' || typeof value === 'boolean';

/** JSON with sorted object keys; the canonical form used for manifest hashing. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function limitOf(
  value: unknown,
  fallback: number,
  max: number,
  name: string,
  errors: string[],
): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    errors.push(`limits.${name} must be an integer between 1 and ${max}`);
    return fallback;
  }
  return value;
}

function byRef<T extends { key: string; version: number }>(
  errors: string[],
  what: string,
  items: readonly T[],
): Record<string, T> {
  const table: Record<string, T> = {};
  for (const item of items) {
    const ref = refKey(item);
    if (Object.hasOwn(table, ref)) errors.push(`${what} ${ref} is declared twice`);
    table[ref] = item;
  }
  return table;
}

/**
 * Validates system declarations for boot/CI readiness. Anything unknown or ambiguous is an error;
 * the result is frozen and carries an order-independent canonical serialization for hashing.
 * Literals are checked with the owning core's codecs; that core records the provenance.
 */
export function validateDeclarations(
  declarations: SystemDeclarations,
  normalize: Normalize,
): ValidationResult {
  const errors: string[] = [];
  const input: unknown = declarations;
  if (!isRecord(input)) return { ok: false, errors: ['declarations must be an object'] };
  for (const list of ['resources', 'relations', 'policies', 'templates', 'boundaries'] as const) {
    const items = input[list];
    if (!Array.isArray(items)) errors.push(`${list} must be an array`);
    else
      items.forEach((item, i) => isRecord(item) || errors.push(`${list}[${i}] must be an object`));
  }
  const capabilities = input.capabilities;
  if (
    !isRecord(capabilities) ||
    !Array.isArray(capabilities.validators) ||
    !Array.isArray(capabilities.obligationHandlers) ||
    ![
      ...(capabilities.validators as unknown[]),
      ...(capabilities.obligationHandlers as unknown[]),
    ].every((name) => typeof name === 'string' && handlerName.test(name))
  ) {
    errors.push('capabilities must list validator and obligation handler names as name@version');
  }
  if (errors.length > 0) return { ok: false, errors };

  const limitsInput = (isRecord(input.limits) ? input.limits : {}) as DeclarationLimits;
  const limits: Required<DeclarationLimits> = {
    maxPathDepth: limitOf(
      limitsInput.maxPathDepth,
      MAX_PATH_DEPTH,
      MAX_PATH_DEPTH,
      'maxPathDepth',
      errors,
    ),
    maxExpressionNodes: limitOf(
      limitsInput.maxExpressionNodes,
      256,
      10_000,
      'maxExpressionNodes',
      errors,
    ),
    maxRules: limitOf(limitsInput.maxRules, 512, 100_000, 'maxRules', errors),
  };
  const validators = new Set(declarations.capabilities.validators);
  const handlers = new Set(declarations.capabilities.obligationHandlers);

  const checkContextRequirements = (requirements: unknown, at: string) => {
    if (!Array.isArray(requirements))
      return void errors.push(`${at}: contextRequirements must be an array`);
    for (const requirement of requirements as unknown[]) {
      if (
        !isRecord(requirement) ||
        typeof requirement.validator !== 'string' ||
        !validators.has(requirement.validator)
      ) {
        errors.push(
          `${at}: context validator ${String(isRecord(requirement) && requirement.validator)} is not registered`,
        );
      } else if (
        !isRecord(requirement.parameters) ||
        !Object.values(requirement.parameters).every(isScalar)
      ) {
        errors.push(`${at}: validator parameters must be strings or booleans`);
      }
    }
  };

  // Resources.
  const resources: Record<string, ResourceDeclaration> = {};
  for (const [i, resource] of declarations.resources.entries()) {
    const at = `resources[${i}]`;
    if (!isRecord(resource) || typeof resource.key !== 'string' || !identifier.test(resource.key)) {
      errors.push(`${at}: key must be an identifier`);
      continue;
    }
    if (Object.hasOwn(resources, resource.key))
      errors.push(`${at}: resource ${resource.key} is declared twice`);
    resources[resource.key] = resource;
    if (!keyKinds.includes(resource.keyKind)) errors.push(`${at}: unknown key kind`);
    if (!isRecord(resource.fields)) errors.push(`${at}: fields must be an object`);
    else
      for (const [name, field] of Object.entries(resource.fields)) {
        const nullable: unknown = isRecord(field) ? field.nullable : undefined;
        if (
          !identifier.test(name) ||
          !isRecord(field) ||
          !isFieldKind(field.kind) ||
          !['boolean', 'undefined'].includes(typeof nullable)
        ) {
          errors.push(`${at}: invalid field ${name}`);
        }
      }
    if (!isRecord(resource.actions)) errors.push(`${at}: actions must be an object`);
    else
      for (const [name, action] of Object.entries(resource.actions)) {
        const policy: unknown = isRecord(action) ? action.policy : undefined;
        if (
          !identifier.test(name) ||
          !isRecord(policy) ||
          typeof policy.key !== 'string' ||
          !isVersion(policy.version)
        ) {
          errors.push(`${at}: action ${name} needs an explicit policy key@version`);
        }
        const boundary: unknown = isRecord(action) ? action.boundary : undefined;
        if (!boundaryRequirements.includes(boundary as string)) {
          errors.push(
            `${at}: action ${name} needs an explicit boundary requirement (required|optional)`,
          );
        }
      }
  }

  // Relations.
  for (const [i, relation] of declarations.relations.entries()) {
    const at = `relations[${i}]`;
    if (
      !isRecord(relation) ||
      typeof relation.key !== 'string' ||
      !dottedKey.test(relation.key) ||
      !isVersion(relation.version)
    ) {
      errors.push(`${at}: relation needs key and positive version`);
      continue;
    }
    if (!Object.hasOwn(resources, relation.sourceType))
      errors.push(`${at}: source type ${relation.sourceType} is not declared`);
    const target: unknown = relation.target;
    if (
      !isRecord(target) ||
      !(
        target.kind === 'identity' ||
        (target.kind === 'resource' && Object.hasOwn(resources, String(target.type)))
      )
    ) {
      errors.push(`${at}: target must be identity or a declared resource`);
    }
    const binding: unknown = relation.binding;
    if (
      !isRecord(binding) ||
      !(
        binding.kind === 'edgeStore' ||
        (binding.kind === 'domain' && typeof binding.key === 'string' && binding.key.length > 0)
      )
    ) {
      errors.push(`${at}: binding must be edgeStore or a named domain binding`);
    }
  }
  const relations: Record<string, RelationDeclaration> = byRef(
    errors,
    'relation',
    declarations.relations,
  );
  const tables: DeclarationTables = { resources, relations };

  // Policies.
  const policies: Record<string, PermissionPolicy> = byRef(errors, 'policy', declarations.policies);
  for (const [ref, policy] of Object.entries(policies)) {
    const at = `policy ${ref}`;
    if (typeof policy.key !== 'string' || !dottedKey.test(policy.key) || !isVersion(policy.version))
      errors.push(`${at}: invalid key/version`);
    if (policy.lifecycle !== undefined && !lifecycles.includes(policy.lifecycle))
      errors.push(`${at}: invalid lifecycle`);
    if (!Array.isArray(policy.contextRequirements) || !Array.isArray(policy.obligations)) {
      errors.push(`${at}: contextRequirements and obligations must be arrays`);
      continue;
    }
    checkContextRequirements(policy.contextRequirements, at);
    for (const obligation of policy.obligations as unknown[]) {
      if (
        !isRecord(obligation) ||
        typeof obligation.handler !== 'string' ||
        !handlers.has(obligation.handler)
      ) {
        errors.push(
          `${at}: obligation handler ${String(isRecord(obligation) && obligation.handler)} is not registered`,
        );
      }
    }
  }

  // Every action must bind an existing, non-retired policy whose required scope type-checks.
  for (const resource of Object.values(resources)) {
    if (!isRecord(resource.actions) || !isRecord(resource.fields)) continue;
    for (const [action, declaration] of Object.entries(resource.actions)) {
      if (!isRecord(declaration.policy)) continue;
      const ref = refKey(declaration.policy);
      const policy = Object.hasOwn(policies, ref) ? policies[ref] : undefined;
      if (!policy) {
        errors.push(`${resource.key}.${action}: policy ${ref} is not declared`);
        continue;
      }
      if (policy.lifecycle === 'retired')
        errors.push(`${resource.key}.${action}: policy ${ref} is retired`);
      checkExpr(
        policy.requiredScope,
        {
          type: resource.key,
          fields: resource.fields,
          parameters: undefined,
          tables,
          maxDepth: limits.maxPathDepth,
          maxNodes: limits.maxExpressionNodes,
          normalize,
        },
        errors,
        `${resource.key}.${action} requiredScope`,
      );
    }
  }

  // Templates.
  const templates = byRef(errors, 'template', declarations.templates);
  for (const [ref, template] of Object.entries(templates)) {
    const at = `template ${ref}`;
    if (
      typeof template.key !== 'string' ||
      !dottedKey.test(template.key) ||
      !isVersion(template.version)
    ) {
      errors.push(`${at}: invalid key/version`);
      continue;
    }
    const resource = Object.hasOwn(resources, template.resource)
      ? resources[template.resource]
      : undefined;
    if (!resource || !isRecord(resource.fields)) {
      errors.push(`${at}: resource ${String(template.resource)} is not declared`);
      continue;
    }
    if (
      !isRecord(template.parameters) ||
      !Object.entries(template.parameters).every(([n, k]) => identifier.test(n) && isFieldKind(k))
    ) {
      errors.push(`${at}: parameters must map names to field kinds`);
      continue;
    }
    checkExpr(
      template.expression,
      {
        type: resource.key,
        fields: resource.fields,
        parameters: template.parameters,
        tables,
        maxDepth: limits.maxPathDepth,
        maxNodes: limits.maxExpressionNodes,
        normalize,
      },
      errors,
      at,
    );
  }

  // Permission boundaries: typed AST on declared permissions; they restrict and never grant.
  const boundaries: Record<string, PermissionBoundary> = byRef(
    errors,
    'boundary',
    declarations.boundaries,
  );
  for (const [ref, boundary] of Object.entries(boundaries)) {
    const at = `boundary ${ref}`;
    if (
      typeof boundary.key !== 'string' ||
      !dottedKey.test(boundary.key) ||
      !isVersion(boundary.version)
    ) {
      errors.push(`${at}: invalid key/version`);
      continue;
    }
    if (boundary.lifecycle !== undefined && !lifecycles.includes(boundary.lifecycle))
      errors.push(`${at}: invalid lifecycle`);
    if (!Array.isArray(boundary.entries) || boundary.entries.length === 0) {
      errors.push(`${at}: entries must be a non-empty array`);
      continue;
    }
    const seen = new Set<string>();
    for (const [i, entry] of boundary.entries.entries()) {
      const eat = `${at} entries[${i}]`;
      if (!isRecord(entry) || typeof entry.permission !== 'string') {
        errors.push(`${eat}: entry needs a permission`);
        continue;
      }
      if (seen.has(entry.permission)) errors.push(`${eat}: ${entry.permission} appears twice`);
      seen.add(entry.permission);
      const [resourceKey = '', action = ''] = entry.permission.split('.');
      const resource = Object.hasOwn(resources, resourceKey) ? resources[resourceKey] : undefined;
      if (
        !resource ||
        !isRecord(resource.actions) ||
        !isRecord(resource.fields) ||
        !Object.hasOwn(resource.actions, action) ||
        `${resourceKey}.${action}` !== entry.permission
      ) {
        errors.push(`${eat}: permission ${entry.permission} is not declared`);
        continue;
      }
      checkContextRequirements(entry.contextRequirements, eat);
      checkExpr(
        entry.requiredScope,
        {
          type: resource.key,
          fields: resource.fields,
          parameters: undefined,
          tables,
          maxDepth: limits.maxPathDepth,
          maxNodes: limits.maxExpressionNodes,
          normalize,
        },
        errors,
        `${eat} requiredScope`,
      );
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  const sortByRef = <T extends { key: string; version: number }>(items: T[]) =>
    items.sort((a, b) => (refKey(a) < refKey(b) ? -1 : refKey(a) > refKey(b) ? 1 : 0));

  const unique = (items: readonly string[]) => [...new Set(items)].sort();

  const byJson = <T>(items: readonly T[]) =>
    [...items].sort((a, b) => (canonicalJson(a) < canonicalJson(b) ? -1 : 1));

  const normalizedPolicies = sortByRef(
    Object.values(policies).map((policy) => ({
      ...policy,
      contextRequirements: byJson(policy.contextRequirements),
      obligations: unique(policy.obligations.map((o) => o.handler)).map((handler) => ({ handler })),
    })),
  );
  const normalizedBoundaries = sortByRef(
    Object.values(boundaries).map((boundary) => ({
      ...boundary,
      entries: boundary.entries
        .map((entry) => ({ ...entry, contextRequirements: byJson(entry.contextRequirements) }))
        .sort((a, b) => (a.permission < b.permission ? -1 : 1)),
    })),
  );
  const manifest = {
    resources: Object.values(resources).sort((a, b) => (a.key < b.key ? -1 : 1)),
    relations: sortByRef(Object.values(relations)),
    policies: normalizedPolicies,
    templates: sortByRef(Object.values(templates)),
    boundaries: normalizedBoundaries,
    capabilities: {
      validators: unique(declarations.capabilities.validators),
      obligationHandlers: unique(declarations.capabilities.obligationHandlers),
    },
    limits,
  };
  const canonical = canonicalJson(manifest);
  const copy = JSON.parse(canonical) as typeof manifest;

  const index = <T extends { key: string; version?: number }>(
    items: T[],
    key: (item: T) => string,
  ) => Object.fromEntries(items.map((item) => [key(item), item]));

  const result: ValidatedDeclarations = deepFreeze({
    resources: index(copy.resources, (r) => r.key),
    relations: index(copy.relations, refKey),
    policies: index(copy.policies, refKey),
    templates: index(copy.templates, refKey),
    boundaries: index(copy.boundaries, refKey),
    capabilities: copy.capabilities,
    limits: copy.limits,
    canonical,
  });
  return { ok: true, declarations: result };
}
