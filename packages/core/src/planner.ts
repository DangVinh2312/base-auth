import { refKey } from './declarations.js';
import { ConfigurationError, deepFreeze, isDenySafe, lowerExpr, simplify } from './expression.js';
import type { AuthorizationCore } from './runtime.js';
import type {
  AuthorizedPlan,
  AuthoritySnapshot,
  Decision,
  FieldKind,
  PlanExpr,
  RuleFact,
  Scalar,
  TrustedInput,
  UserAuthorizedPlan,
  UserAuthoritySnapshot,
  UserDecision,
  UserTrustedInput,
  ValueRef,
} from './types.js';

class Denied extends Error {}
const deny = (reason: string): never => {
  throw new Denied(reason);
};

/**
 * Builds the authorized plan (spec 4.2):
 * P = policy.requiredScope AND boundary.requiredScope AND (allow scopes OR record allow)
 *     AND NOT (deny scopes OR record deny).
 * The permission boundary (ADR 0003) is one more AND outside every allow; it never grants.
 * Tenant and membership are hard boundaries checked first. Any missing, unknown or malformed fact
 * or configuration denies; nothing is skipped or truncated. Pure: no I/O, inputs are not mutated.
 */
export function plan(
  core: AuthorizationCore,
  input: TrustedInput,
  snapshot: AuthoritySnapshot,
): Decision {
  try {
    if (!core.isValidated(snapshot.declarations)) deny('unvalidated_declarations');
    if (!core.isCanonicalUuid(input.tenant) || input.tenant !== snapshot.tenant)
      deny('tenant_mismatch');
    const membership = snapshot.membership ?? deny('inactive_membership');
    if (membership.identity !== input.principal.id || membership.state !== 'active')
      deny('inactive_membership');
    const decision = buildPlan(core, input, {
      ...snapshot,
      user: { id: membership.identity, state: membership.state },
    });
    if (decision.effect === 'deny') return decision;
    const { userId, ...common } = decision.plan;
    const authorized: AuthorizedPlan = deepFreeze({
      ...common,
      tenant: input.tenant,
      identity: userId,
    });
    return { effect: 'allow', plan: authorized, obligations: authorized.obligations };
  } catch (error) {
    if (error instanceof Denied) return { effect: 'deny', internalReason: error.message };
    if (error instanceof ConfigurationError)
      return { effect: 'deny', internalReason: `configuration: ${error.message}` };
    return { effect: 'deny', internalReason: 'internal_error' };
  }
}

/** Product entry point: no tenant routing or membership is involved. */
export function planUser(
  core: AuthorizationCore,
  input: UserTrustedInput,
  snapshot: UserAuthoritySnapshot,
): UserDecision {
  try {
    return buildPlan(core, input, snapshot);
  } catch (error) {
    if (error instanceof Denied) return { effect: 'deny', internalReason: error.message };
    if (error instanceof ConfigurationError)
      return { effect: 'deny', internalReason: `configuration: ${error.message}` };
    return { effect: 'deny', internalReason: 'internal_error' };
  }
}

function buildPlan(
  core: AuthorizationCore,
  input: UserTrustedInput,
  snapshot: UserAuthoritySnapshot,
): UserDecision {
  const declarations = snapshot.declarations;
  if (!core.isValidated(declarations)) deny('unvalidated_declarations');

  const principal = input.principal;
  if (!core.isCanonicalUuid(principal.id) || typeof principal.assurance !== 'number')
    deny('invalid_principal');
  if (snapshot.user?.id !== principal.id || snapshot.user.state !== 'active') deny('inactive_user');
  const now = core.canonicalTimestamp(input.now) ?? deny('invalid_now');
  const validUntil = core.canonicalTimestamp(input.validUntil) ?? deny('invalid_valid_until');
  if (core.compareValues('timestamp', validUntil, now) <= 0) deny('invalid_validity_window');

  // Registered resource/action, catalog binding and its exact policy version.
  const resource = Object.hasOwn(declarations.resources, input.resource)
    ? declarations.resources[input.resource]!
    : deny('unknown_resource');
  const action = Object.hasOwn(resource.actions, input.action)
    ? resource.actions[input.action]!
    : deny('unknown_action');
  const permissionKey = `${resource.key}.${input.action}`;
  const permission =
    snapshot.permissions.find((p) => p.key === permissionKey) ?? deny('permission_not_in_catalog');
  if (
    permission.resource !== resource.key ||
    permission.action !== input.action ||
    permission.lifecycle === 'retired'
  ) {
    deny('permission_unavailable');
  }
  if (refKey(permission.policy) !== refKey(action.policy)) deny('policy_binding_mismatch');
  const policyRef = refKey(action.policy);
  const policy = Object.hasOwn(declarations.policies, policyRef)
    ? declarations.policies[policyRef]!
    : deny('policy_missing');
  if (policy.lifecycle === 'retired') deny('policy_retired');

  // Context requirements: only `true` passes; false/unknown/throw/missing validator deny.
  const requireContext = (requirements: typeof policy.contextRequirements) => {
    for (const requirement of requirements) {
      const validator = Object.hasOwn(snapshot.registry.validators, requirement.validator)
        ? snapshot.registry.validators[requirement.validator]!
        : deny('validator_unavailable');
      let result: unknown;
      try {
        result = validator(requirement.parameters, { principal, context: input.context });
      } catch {
        deny('validator_failed');
      }
      if (result !== true) deny('context_requirement_failed');
    }
  };
  requireContext(policy.contextRequirements);

  // Permission boundary: the stored requirement must equal the code's; exactly the user's
  // own binding applies; a bound definition, its exact version and entry must all exist.
  if (permission.boundary !== action.boundary) deny('boundary_requirement_mismatch');
  const bindings = snapshot.boundaries.filter(
    (b) => b.identity === principal.id && b.permission === permissionKey,
  );
  if (bindings.length > 1) deny('ambiguous_boundary_binding');
  const binding = bindings[0];
  let boundaryEntry: (typeof declarations.boundaries)[string]['entries'][number] | undefined;
  if (binding === undefined) {
    if (action.boundary !== 'optional') deny('boundary_binding_missing');
  } else {
    const ref = refKey(binding.boundary);
    const boundary = Object.hasOwn(declarations.boundaries, ref)
      ? declarations.boundaries[ref]!
      : deny('boundary_definition_missing');
    if (
      (binding.lifecycle !== 'active' && binding.lifecycle !== 'deprecated') ||
      boundary.lifecycle === 'retired'
    ) {
      deny('boundary_unavailable');
    }
    boundaryEntry =
      boundary.entries.find((e) => e.permission === permissionKey) ??
      deny('boundary_entry_missing');
    requireContext(boundaryEntry.contextRequirements);
  }
  const obligations = policy.obligations.map((o) => ({ handler: o.handler }));
  for (const obligation of obligations) {
    if (!snapshot.registry.obligationHandlers.includes(obligation.handler))
      deny('obligation_handler_unavailable');
  }

  const resolveCommon = (ref: ValueRef, kind: FieldKind): Scalar | undefined => {
    if (ref.from === 'literal') return core.normalizeValue(kind, ref.value);
    if (ref.from === 'principal' && ref.name === 'id')
      return core.normalizeValue(kind, principal.id);
    if (ref.from === 'context' && Object.hasOwn(input.context, ref.name))
      return core.normalizeValue(kind, input.context[ref.name]);
    return undefined;
  };
  const bind =
    (parameters: RuleFact['parameters'] | undefined) =>
    (ref: ValueRef, kind: FieldKind): Scalar => {
      const value =
        ref.from === 'parameter'
          ? parameters && Object.hasOwn(parameters, ref.name)
            ? core.normalizeValue(kind, parameters[ref.name])
            : undefined
          : resolveCommon(ref, kind);
      return value ?? deny(`unresolved_value:${ref.from}`);
    };
  const tables = { resources: declarations.resources, relations: declarations.relations };

  // Applicable rules: this permission, an assigned role or this identity.
  const roles = [...new Set(snapshot.roles)].sort();
  const applicable = snapshot.rules.filter(
    (rule) =>
      rule.permission === permissionKey &&
      (rule.subject.kind === 'role'
        ? roles.includes(rule.subject.role)
        : rule.subject.identity === principal.id),
  );
  if (applicable.length > declarations.limits.maxRules) deny('too_many_rules');

  const allow: PlanExpr[] = [];
  const denies: PlanExpr[] = [];
  for (const rule of applicable) {
    const ref = refKey(rule.template);
    const template = Object.hasOwn(declarations.templates, ref)
      ? declarations.templates[ref]!
      : deny('unknown_template');
    if (template.resource !== resource.key) deny('template_resource_mismatch');
    const expected = Object.keys(template.parameters).sort();
    const given = Object.keys(rule.parameters).sort();
    if (expected.join('\u0000') !== given.join('\u0000')) deny('rule_parameters_mismatch');
    if (rule.effect !== 'allow' && rule.effect !== 'deny') deny('unknown_effect');
    if (rule.effect === 'deny' && !isDenySafe(template.expression, resource.fields))
      deny('unsafe_deny_template');
    const lowered = lowerExpr(
      template.expression,
      resource.key,
      resource.fields,
      tables,
      bind(rule.parameters),
    );
    (rule.effect === 'allow' ? allow : denies).push(lowered);
  }
  const exception = (effect: 'allow' | 'deny'): PlanExpr => ({
    op: 'exception',
    effect,
    permission: permissionKey,
    identity: principal.id,
    roles,
  });
  const required = lowerExpr(
    policy.requiredScope,
    resource.key,
    resource.fields,
    tables,
    bind(undefined),
  );
  const boundaryScope: PlanExpr = boundaryEntry
    ? lowerExpr(boundaryEntry.requiredScope, resource.key, resource.fields, tables, bind(undefined))
    : { op: 'constant', value: true }; // optional and unbound only
  const predicate = simplify({
    op: 'and',
    args: [
      required,
      boundaryScope,
      { op: 'or', args: [...allow, exception('allow')] },
      { op: 'not', arg: { op: 'or', args: [...denies, exception('deny')] } },
    ],
  });

  const authorized: UserAuthorizedPlan = deepFreeze({
    userId: principal.id,
    resource: resource.key,
    action: input.action,
    permission: permissionKey,
    revision: snapshot.revision,
    predicate,
    validUntil,
    obligations,
  });
  return { effect: 'allow', plan: authorized, obligations: authorized.obligations };
}
