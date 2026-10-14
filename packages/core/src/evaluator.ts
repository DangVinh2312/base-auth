import type { AuthorizationCore } from './runtime.js';
import type {
  AuthorizedPlan,
  CompleteFacts,
  Decision,
  FactObject,
  IdentityId,
  PlanExpr,
  UserAuthorizedPlan,
  UserCompleteFacts,
  UserDecision,
} from './types.js';

class InvalidFact extends Error {}
const invalid = (reason: string): never => {
  throw new InvalidFact(reason);
};

type Current =
  | { readonly kind: 'object'; readonly object: FactObject }
  | { readonly kind: 'identity'; readonly identity: IdentityId };

/**
 * Decides one record against a plan with complete facts. Used for record checks and differential
 * tests against SQL; it does not replace query enforcement. Malformed or missing facts deny.
 */
export function evaluate(
  core: AuthorizationCore,
  plan: AuthorizedPlan,
  facts: CompleteFacts,
): Decision {
  try {
    if (facts.tenant !== plan.tenant) return { effect: 'deny', internalReason: 'tenant_mismatch' };
    return evaluatePlan(core, plan, {
      ...facts,
      edges: facts.edges.filter((edge) => edge.tenant === plan.tenant),
      exceptions: facts.exceptions.filter((exception) => exception.tenant === plan.tenant),
    });
  } catch {
    return { effect: 'deny', internalReason: 'internal_error' };
  }
}

export function evaluateUser(
  core: AuthorizationCore,
  plan: UserAuthorizedPlan,
  facts: UserCompleteFacts,
): UserDecision {
  return evaluatePlan(core, plan, facts);
}

function evaluatePlan<P extends AuthorizedPlan | UserAuthorizedPlan>(
  core: AuthorizationCore,
  plan: P,
  facts: UserCompleteFacts,
):
  | { readonly effect: 'deny'; readonly internalReason: string }
  | {
      readonly effect: 'allow';
      readonly plan: P;
      readonly obligations: P['obligations'];
    } {
  try {
    const time = (value: string) => core.canonicalTimestamp(value) ?? invalid('invalid_time');
    const compareTime = (a: string, b: string) => core.compareValues('timestamp', a, b);
    const now = core.canonicalTimestamp(facts.now) ?? invalid('invalid_now');
    if (compareTime(now, plan.validUntil) >= 0)
      return { effect: 'deny', internalReason: 'plan_expired' };
    if (facts.record.type !== plan.resource)
      return { effect: 'deny', internalReason: 'resource_mismatch' };
    const active = (startsAt: string, expiresAt: string | null) => {
      const end = expiresAt === null ? null : time(expiresAt);
      return compareTime(time(startsAt), now) <= 0 && (end === null || compareTime(end, now) > 0);
    };

    const test = (expr: PlanExpr, current: Current): boolean => {
      switch (expr.op) {
        case 'constant':
          return expr.value;
        case 'and':
          return expr.args.every((arg) => test(arg, current));
        case 'or':
          return expr.args.some((arg) => test(arg, current));
        case 'not':
          return !test(expr.arg, current);
        case 'isNull':
          return field(current, expr.field) === null;
        case 'eq':
        case 'lt':
        case 'lte': {
          const raw = field(current, expr.field);
          if (raw === null) return false; // null never matches a comparison
          const value = core.normalizeValue(expr.kind, raw) ?? invalid(`invalid_${expr.kind}_fact`);
          const order = core.compareValues(expr.kind, value, expr.value);
          return expr.op === 'eq' ? order === 0 : expr.op === 'lt' ? order < 0 : order <= 0;
        }
        case 'exists': {
          if (current.kind !== 'object' || current.object.type !== expr.source) return false;
          return facts.edges.some((edge) => {
            if (
              edge.relation.key !== expr.relation.key ||
              edge.relation.version !== expr.relation.version ||
              edge.source !== current.object.objectId ||
              !active(edge.startsAt, edge.expiresAt)
            ) {
              return false;
            }
            if (expr.target.kind === 'identity') {
              return (
                edge.target.kind === 'identity' &&
                test(expr.where, { kind: 'identity', identity: edge.target.identity })
              );
            }
            const type = expr.target.type;
            const target =
              edge.target.kind === 'object'
                ? facts.objects.find(
                    (o) =>
                      o.objectId === (edge.target as { objectId: string }).objectId &&
                      o.type === type,
                  )
                : undefined;
            return target !== undefined && test(expr.where, { kind: 'object', object: target });
          });
        }
        case 'exception': {
          const record = facts.record;
          return facts.exceptions.some(
            (x) =>
              x.objectId === record.objectId &&
              x.permission === expr.permission &&
              x.effect === expr.effect &&
              // Emergency allows need the D3 activation contract (later task); until then they never grant.
              (x.effect === 'deny' || x.purpose === 'manual') &&
              x.revokedAt === null &&
              (x.subject.kind === 'identity'
                ? x.subject.identity === expr.identity
                : expr.roles.includes(x.subject.role)) &&
              active(x.startsAt, x.expiresAt),
          );
        }
      }
    };

    const allowed = test(plan.predicate, { kind: 'object', object: facts.record });
    return allowed
      ? { effect: 'allow', plan, obligations: plan.obligations }
      : { effect: 'deny', internalReason: 'predicate_false' };
  } catch (error) {
    return {
      effect: 'deny',
      internalReason: error instanceof InvalidFact ? error.message : 'internal_error',
    };
  }
}

function field(current: Current, name: string) {
  if (current.kind === 'identity')
    return name === 'identityId' ? current.identity : invalid('missing_fact');
  return Object.hasOwn(current.object.fields, name)
    ? current.object.fields[name]!
    : invalid('missing_fact');
}
