import type { FieldType, RelationDeclaration, ResourceDeclaration } from './declarations.js';
import type { Expr, FieldKind, PlanExpr, Scalar, ValueRef } from './types.js';

/** Context type reached through a relation whose target is an identity. */
export const IDENTITY_FIELDS: Readonly<Record<string, FieldType>> = Object.freeze({
  identityId: Object.freeze({ kind: 'uuid' }),
});
export const MAX_PATH_DEPTH = 8;

export const fieldKinds: readonly FieldKind[] = [
  'integer',
  'decimal',
  'string',
  'uuid',
  'boolean',
  'timestamp',
];
const orderedKinds: readonly FieldKind[] = ['integer', 'decimal', 'string', 'timestamp'];
export const isFieldKind = (value: unknown): value is FieldKind =>
  fieldKinds.includes(value as FieldKind);

/** Instance normalization (see runtime.ts); undefined when the value does not have that kind. */
export type Normalize = (kind: FieldKind, value: unknown) => Scalar | undefined;

export interface DeclarationTables {
  readonly resources: Readonly<Record<string, ResourceDeclaration>>;
  readonly relations: Readonly<Record<string, RelationDeclaration>>;
}

export function relationTargetFields(
  relation: RelationDeclaration,
  tables: DeclarationTables,
): Readonly<Record<string, FieldType>> | undefined {
  return relation.target.kind === 'identity'
    ? IDENTITY_FIELDS
    : Object.hasOwn(tables.resources, relation.target.type)
      ? tables.resources[relation.target.type]!.fields
      : undefined;
}

export interface CheckContext {
  readonly type: string;
  readonly fields: Readonly<Record<string, FieldType>>;
  /** Template parameters; undefined for policy required scopes (no parameters allowed). */
  readonly parameters: Readonly<Record<string, FieldKind>> | undefined;
  readonly tables: DeclarationTables;
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly normalize: Normalize;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Type-checks a declaration expression. Unknown shapes are errors: the core fails closed. */
export function checkExpr(expr: unknown, ctx: CheckContext, errors: string[], at: string): void {
  let nodes = 0;
  const visit = (
    node: unknown,
    type: string,
    fields: CheckContext['fields'],
    depth: number,
    path: string,
  ) => {
    if (++nodes > ctx.maxNodes) {
      if (nodes === ctx.maxNodes + 1)
        errors.push(`${at}: more than ${ctx.maxNodes} expression nodes`);
      return;
    }
    if (!isRecord(node)) return void errors.push(`${path}: expression must be an object`);
    switch (node.op) {
      case 'constant':
        if (typeof node.value !== 'boolean') errors.push(`${path}: constant must be boolean`);
        return;
      case 'and':
      case 'or':
        if (!Array.isArray(node.args) || node.args.length === 0)
          return void errors.push(`${path}: ${String(node.op)} needs arguments`);
        node.args.forEach((arg: unknown, i) =>
          visit(arg, type, fields, depth, `${path}.${String(node.op)}[${i}]`),
        );
        return;
      case 'eq':
      case 'lt':
      case 'lte': {
        const field =
          typeof node.field === 'string' && Object.hasOwn(fields, node.field)
            ? fields[node.field]
            : undefined;
        if (!field)
          return void errors.push(`${path}: unknown field ${String(node.field)} on ${type}`);
        if (node.op !== 'eq' && !orderedKinds.includes(field.kind)) {
          errors.push(`${path}: ${node.op} is not defined for ${field.kind}`);
        }
        checkValueRef(node.value, field.kind, ctx, errors, path);
        return;
      }
      case 'isNull': {
        const field =
          typeof node.field === 'string' && Object.hasOwn(fields, node.field)
            ? fields[node.field]
            : undefined;
        if (!field?.nullable) errors.push(`${path}: isNull needs a nullable field`);
        return;
      }
      case 'exists': {
        const relation =
          typeof node.relation === 'string' && Object.hasOwn(ctx.tables.relations, node.relation)
            ? ctx.tables.relations[node.relation]
            : undefined;
        if (!relation)
          return void errors.push(`${path}: unknown relation ${String(node.relation)}`);
        if (relation.sourceType !== type) {
          return void errors.push(
            `${path}: relation ${String(node.relation)} starts at ${relation.sourceType}, not ${type}`,
          );
        }
        if (depth + 1 > ctx.maxDepth)
          return void errors.push(`${path}: relation path deeper than ${ctx.maxDepth}`);
        const targetFields = relationTargetFields(relation, ctx.tables);
        if (!targetFields) return void errors.push(`${path}: relation target is not declared`);
        const targetType = relation.target.kind === 'identity' ? 'identity' : relation.target.type;
        visit(node.where, targetType, targetFields, depth + 1, `${path}.exists`);
        return;
      }
      default:
        errors.push(`${path}: unsupported operator ${JSON.stringify(node.op)}`);
    }
  };
  visit(expr, ctx.type, ctx.fields, 0, at);
}

function checkValueRef(
  ref: unknown,
  kind: FieldKind,
  ctx: CheckContext,
  errors: string[],
  path: string,
): void {
  const parameters = ctx.parameters;
  if (!isRecord(ref)) return void errors.push(`${path}: value must be a typed reference`);
  switch (ref.from) {
    case 'literal':
      if (ctx.normalize(kind, ref.value) === undefined)
        errors.push(`${path}: literal is not a valid ${kind}`);
      return;
    case 'principal':
      if (ref.name !== 'id' || kind !== 'uuid')
        errors.push(`${path}: only principal.id (uuid) is available`);
      return;
    case 'context':
      if (typeof ref.name !== 'string' || ref.name.length === 0)
        errors.push(`${path}: context name required`);
      return;
    case 'parameter':
      if (
        !parameters ||
        typeof ref.name !== 'string' ||
        !Object.hasOwn(parameters, ref.name) ||
        parameters[ref.name] !== kind
      ) {
        errors.push(`${path}: parameter ${String(ref.name)} is not declared as ${kind}`);
      }
      return;
    default:
      errors.push(`${path}: unsupported value source ${JSON.stringify(ref.from)}`);
  }
}

/**
 * A deny scope must never evaluate to SQL NULL, otherwise NOT(deny) would differ between SQL and
 * the evaluator. Comparisons on nullable fields outside an EXISTS are therefore rejected for deny.
 */
export function isDenySafe(expr: Expr, fields: Readonly<Record<string, FieldType>>): boolean {
  switch (expr.op) {
    case 'and':
    case 'or':
      return expr.args.every((arg) => isDenySafe(arg, fields));
    case 'eq':
    case 'lt':
    case 'lte':
      return fields[expr.field]?.nullable !== true;
    default:
      return true;
  }
}

export class ConfigurationError extends Error {}

/** Lowers a checked expression into a typed plan expression, binding every value. */
export function lowerExpr(
  expr: Expr,
  type: string,
  fields: Readonly<Record<string, FieldType>>,
  tables: DeclarationTables,
  resolve: (ref: ValueRef, kind: FieldKind) => Scalar,
): PlanExpr {
  switch (expr.op) {
    case 'constant':
      return { op: 'constant', value: expr.value };
    case 'and':
    case 'or':
      return {
        op: expr.op,
        args: expr.args.map((arg) => lowerExpr(arg, type, fields, tables, resolve)),
      };
    case 'eq':
    case 'lt':
    case 'lte': {
      const field = Object.hasOwn(fields, expr.field) ? fields[expr.field] : undefined;
      if (!field) throw new ConfigurationError(`unknown field ${expr.field} on ${type}`);
      return {
        op: expr.op,
        field: expr.field,
        kind: field.kind,
        value: resolve(expr.value, field.kind),
      };
    }
    case 'isNull':
      return { op: 'isNull', field: expr.field };
    case 'exists': {
      const relation = Object.hasOwn(tables.relations, expr.relation)
        ? tables.relations[expr.relation]
        : undefined;
      const targetFields = relation && relationTargetFields(relation, tables);
      if (!relation || !targetFields || relation.sourceType !== type) {
        throw new ConfigurationError(`invalid relation ${expr.relation} from ${type}`);
      }
      const targetType = relation.target.kind === 'identity' ? 'identity' : relation.target.type;
      return {
        op: 'exists',
        relation: { key: relation.key, version: relation.version },
        source: type,
        target:
          relation.target.kind === 'identity'
            ? { kind: 'identity' }
            : { kind: 'resource', type: relation.target.type },
        where: lowerExpr(expr.where, targetType, targetFields, tables, resolve),
      };
    }
    default:
      throw new ConfigurationError('unsupported operator');
  }
}

/** Constant folding only; never reorders or drops a deny branch that is not provably false. */
export function simplify(expr: PlanExpr): PlanExpr {
  switch (expr.op) {
    case 'and':
    case 'or': {
      const absorbing = expr.op === 'or';
      const args: PlanExpr[] = [];
      for (const arg of expr.args.map(simplify)) {
        if (arg.op === 'constant') {
          if (arg.value === absorbing) return arg;
          continue;
        }
        args.push(arg);
      }
      if (args.length === 0) return { op: 'constant', value: !absorbing };
      return args.length === 1 ? args[0]! : { op: expr.op, args };
    }
    case 'not': {
      const arg = simplify(expr.arg);
      return arg.op === 'constant' ? { op: 'constant', value: !arg.value } : { op: 'not', arg };
    }
    case 'exists':
      return { ...expr, where: simplify(expr.where) };
    default:
      return expr;
  }
}

export function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
