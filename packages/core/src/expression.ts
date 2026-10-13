import type { FieldType, RelationDeclaration, ResourceDeclaration } from './declarations.js';
import { canonicalInt64, compareText, isWellFormedText } from './key-codec.js';
import type { Expr, FieldKind, PlanExpr, Scalar, ValueRef } from './types.js';

/** Context type reached through a relation whose target is an identity. */
export const IDENTITY_FIELDS: Readonly<Record<string, FieldType>> = Object.freeze({
  identityId: Object.freeze({ kind: 'uuid' }),
});
export const MAX_PATH_DEPTH = 8;

const fieldKinds: readonly FieldKind[] = [
  'integer',
  'decimal',
  'string',
  'uuid',
  'boolean',
  'timestamp',
];
const orderedKinds: readonly FieldKind[] = ['integer', 'decimal', 'string', 'timestamp'];
const decimalPattern = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$/;
const timestampPattern = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$/;
const anyUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const isFieldKind = (value: unknown): value is FieldKind =>
  fieldKinds.includes(value as FieldKind);

/** UTC timestamp with exactly 6 fractional digits, so string order is time order. */
export function canonicalTimestamp(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const match = timestampPattern.exec(value);
  if (!match || Number.isNaN(Date.parse(`${match[1]}Z`))) return undefined;
  return `${match[1]}.${(match[2] ?? '').padEnd(6, '0')}Z`;
}

/** Normalizes a value for a field kind; undefined when the value does not have that type. */
export function normalizeValue(kind: FieldKind, value: unknown): Scalar | undefined {
  switch (kind) {
    case 'integer':
      return canonicalInt64(value);
    case 'decimal':
      return typeof value === 'string' && decimalPattern.test(value) ? value : undefined;
    case 'string':
      return isWellFormedText(value) ? value : undefined;
    case 'uuid':
      return typeof value === 'string' && anyUuid.test(value) ? value.toLowerCase() : undefined;
    case 'boolean':
      return typeof value === 'boolean' ? value : undefined;
    case 'timestamp':
      return canonicalTimestamp(value);
  }
}

function compareDecimal(a: string, b: string): number {
  const parse = (text: string) => {
    const [, sign = '', whole = '0', fraction = ''] = decimalPattern.exec(text) ?? [];
    const digits = fraction.replace(/0+$/, '');
    const negative = sign === '-' && (whole !== '0' || digits !== '');
    return { negative, whole, digits };
  };
  const x = parse(a);
  const y = parse(b);
  if (x.negative !== y.negative) return x.negative ? -1 : 1;
  const magnitude = () => {
    if (x.whole.length !== y.whole.length) return x.whole.length - y.whole.length;
    if (x.whole !== y.whole) return x.whole < y.whole ? -1 : 1;
    const width = Math.max(x.digits.length, y.digits.length);
    const xf = x.digits.padEnd(width, '0');
    const yf = y.digits.padEnd(width, '0');
    return xf === yf ? 0 : xf < yf ? -1 : 1;
  };
  return x.negative ? -magnitude() : magnitude();
}

/** Exact comparison of two normalized values of the same kind. */
export function compareValues(kind: FieldKind, a: Scalar, b: Scalar): number {
  if (kind === 'boolean' || kind === 'uuid') return a === b ? 0 : 1;
  const left = String(a);
  const right = String(b);
  if (kind === 'integer') {
    const diff = BigInt(left) - BigInt(right);
    return diff === 0n ? 0 : diff < 0n ? -1 : 1;
  }
  if (kind === 'decimal') return compareDecimal(left, right);
  if (kind === 'string') return compareText(left, right);
  return left === right ? 0 : left < right ? -1 : 1; // canonical timestamps
}

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
        checkValueRef(node.value, field.kind, ctx.parameters, errors, path);
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
  parameters: CheckContext['parameters'],
  errors: string[],
  path: string,
): void {
  if (!isRecord(ref)) return void errors.push(`${path}: value must be a typed reference`);
  switch (ref.from) {
    case 'literal':
      if (normalizeValue(kind, ref.value) === undefined)
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
