import {
  type AuthorizationCore,
  type UserAuthorizedPlan,
  type FieldKind,
  type KeyKind,
  type PlanExpr,
  refKey,
  type ValidatedDeclarations,
} from '@base-authorization/core';

/** Maps a declared resource onto its business table. Columns and table names are identifiers only. */
export interface ProductResourceBinding {
  readonly resource: string;
  readonly table: string;
  /** Column holding the object registry UUID (UNIQUE(object_id) + FK to object_ref). */
  readonly objectIdColumn: string;
  /** Native primary key column; compared with typed binds, never cast. */
  readonly keyColumn: string;
  readonly columns: Readonly<Record<string, string>>;
  /** Fields a reader may receive, filter or sort on. Everything else stays hidden. */
  readonly projection: readonly string[];
}

/** Relation stored in an existing domain table (spec 6: bind to assignment tables, no copies). */
export interface ProductDomainRelationBinding {
  readonly table: string;
  /** References the source resource's native key column. */
  readonly sourceColumn: string;
  /** Identity UUID column (identity targets only in this version). */
  readonly targetColumn: string;
  readonly startsColumn?: string;
  readonly expiresColumn?: string;
}

export interface ProductStorageBindings {
  readonly resources: readonly ProductResourceBinding[];
  readonly domains: Readonly<Record<string, ProductDomainRelationBinding>>;
}

export interface BoundPredicate {
  readonly sql: string;
  readonly parameters: readonly unknown[];
}

const identifier = /^[a-z_][a-z0-9_]{0,62}$/;
export const quoteIdentifier = (name: string): string => {
  if (!identifier.test(name)) throw new TypeError(`Unsafe SQL identifier: ${JSON.stringify(name)}`);
  return `"${name}"`;
};

export const fieldPgTypes: Readonly<Record<FieldKind, string>> = {
  integer: 'int8',
  decimal: 'numeric',
  string: 'text',
  uuid: 'uuid',
  boolean: 'boolean',
  timestamp: 'timestamptz',
};
export const keyPgTypes: Readonly<Record<KeyKind, string>> = {
  integer: 'int8',
  uuid: 'uuid',
  string: 'text',
};

/**
 * Validated resource and relation bindings. Construction fails (readiness) when a declared
 * resource, field or domain relation has no binding, or when any identifier is unsafe.
 */
export class ProductBindingRegistry {
  readonly declarations: ValidatedDeclarations;
  readonly #resources = new Map<string, ProductResourceBinding>();
  readonly #domains = new Map<string, ProductDomainRelationBinding>();

  /** Validated `declarations` must come from this core; the gateway normalizes with it too. */
  constructor(
    readonly core: AuthorizationCore,
    declarations: ValidatedDeclarations,
    bindings: ProductStorageBindings,
  ) {
    if (!core.isValidated(declarations))
      throw new TypeError('Declarations must come from validate() of this authorization core');
    this.declarations = declarations;
    for (const binding of bindings.resources) {
      const resource = Object.hasOwn(declarations.resources, binding.resource)
        ? declarations.resources[binding.resource]
        : undefined;
      if (!resource) throw new TypeError(`Binding for undeclared resource ${binding.resource}`);
      if (this.#resources.has(binding.resource))
        throw new TypeError(`Resource ${binding.resource} bound twice`);
      for (const name of [binding.table, binding.objectIdColumn, binding.keyColumn])
        quoteIdentifier(name);
      for (const field of Object.keys(resource.fields)) {
        if (field === 'key')
          throw new TypeError(`Field name "key" is reserved (${binding.resource})`);
        if (!Object.hasOwn(binding.columns, field))
          throw new TypeError(`Field ${binding.resource}.${field} has no column`);
        quoteIdentifier(binding.columns[field]!);
      }
      for (const field of binding.projection) {
        if (!Object.hasOwn(resource.fields, field))
          throw new TypeError(`Projection field ${binding.resource}.${field} is not declared`);
      }
      this.#resources.set(
        binding.resource,
        Object.freeze({ ...binding, projection: [...binding.projection] }),
      );
    }
    for (const key of Object.keys(declarations.resources)) {
      if (!this.#resources.has(key)) throw new TypeError(`Resource ${key} has no storage binding`);
    }
    for (const relation of Object.values(declarations.relations)) {
      if (relation.binding.kind !== 'domain') continue;
      const domain = Object.hasOwn(bindings.domains, relation.binding.key)
        ? bindings.domains[relation.binding.key]
        : undefined;
      if (!domain)
        throw new TypeError(
          `Relation ${refKey(relation)} has no domain binding ${relation.binding.key}`,
        );
      if (relation.target.kind !== 'identity') {
        throw new TypeError(
          `Relation ${refKey(relation)}: domain bindings to resources are not supported yet`,
        );
      }
      for (const name of [domain.table, domain.sourceColumn, domain.targetColumn])
        quoteIdentifier(name);
      if ((domain.startsColumn === undefined) !== (domain.expiresColumn === undefined))
        throw new TypeError(
          'Domain relation validity requires both startsColumn and expiresColumn',
        );
      if (domain.startsColumn !== undefined) quoteIdentifier(domain.startsColumn);
      if (domain.expiresColumn !== undefined) quoteIdentifier(domain.expiresColumn);
      this.#domains.set(refKey(relation), Object.freeze({ ...domain }));
    }
  }

  resource(name: string): ProductResourceBinding {
    const binding = this.#resources.get(name);
    if (!binding) throw new TypeError(`Resource ${name} has no storage binding`);
    return binding;
  }

  domain(relationRef: string): ProductDomainRelationBinding | undefined {
    return this.#domains.get(relationRef);
  }
}

/** Emits a placeholder for a value with an explicit PostgreSQL type; values never enter SQL text. */
export type Bind = (value: unknown, pgType: string) => string;

type Scope =
  | { readonly kind: 'resource'; readonly alias: string; readonly binding: ProductResourceBinding }
  | { readonly kind: 'identity'; readonly column: string };

const utf8 = (value: string) => Buffer.from(value, 'utf8');
const comparison = { eq: '=', lt: '<', lte: '<=' } as const;

/** Compiles a plan expression in the scope of `alias` (allow-listed aliases only: r, e<n>, t<n>, x<n>). */
export function compileExpression(
  expr: PlanExpr,
  registry: ProductBindingRegistry,
  scope: Scope,
  bind: Bind,
  nextAlias: (prefix: 'e' | 't' | 'x') => string,
): string {
  const compile = (node: PlanExpr, current: Scope): string => {
    switch (node.op) {
      case 'constant':
        return node.value ? 'TRUE' : 'FALSE';
      case 'and':
      case 'or':
        return `(${node.args.map((arg) => compile(arg, current)).join(node.op === 'and' ? ' AND ' : ' OR ')})`;
      case 'not':
        return `(NOT ${compile(node.arg, current)})`;
      case 'isNull':
        return `${column(current, node.field)} IS NULL`;
      case 'eq':
      case 'lt':
      case 'lte': {
        const collate = node.kind === 'string' && node.op !== 'eq' ? ' COLLATE "C"' : '';
        return `${column(current, node.field)}${collate} ${comparison[node.op]} ${bind(node.value, fieldPgTypes[node.kind])}`;
      }
      case 'exists':
        return exists(node, current);
      case 'exception':
        return exception(node, current);
    }
  };

  const column = (current: Scope, field: string): string => {
    if (current.kind === 'identity') {
      if (field !== 'identityId') throw new TypeError(`Unknown identity field ${field}`);
      return current.column;
    }
    const name = Object.hasOwn(current.binding.columns, field)
      ? current.binding.columns[field]
      : undefined;
    if (!name) throw new TypeError(`Unknown field ${current.binding.resource}.${field}`);
    return `${current.alias}.${quoteIdentifier(name)}`;
  };

  const active = (alias: string, starts: string, expires: string) =>
    `${alias}.${quoteIdentifier(starts)} <= statement_timestamp() AND (${alias}.${quoteIdentifier(expires)} IS NULL OR ${alias}.${quoteIdentifier(expires)} > statement_timestamp())`;

  const exists = (node: Extract<PlanExpr, { op: 'exists' }>, current: Scope): string => {
    if (current.kind !== 'resource' || current.binding.resource !== node.source) {
      throw new TypeError(`Relation ${refKey(node.relation)} does not start at this scope`);
    }
    const ref = refKey(node.relation);
    const relation = Object.hasOwn(registry.declarations.relations, ref)
      ? registry.declarations.relations[ref]
      : undefined;
    if (!relation) throw new TypeError(`Unknown relation ${ref}`);
    const outer = current.alias;
    const src = current.binding;
    const e = nextAlias('e');
    if (relation.binding.kind === 'domain') {
      const d = registry.domain(ref);
      if (!d || node.target.kind !== 'identity')
        throw new TypeError(`Relation ${ref} has no usable domain binding`);
      const window =
        d.startsColumn && d.expiresColumn
          ? ` AND ${active(e, d.startsColumn, d.expiresColumn)}`
          : '';
      return (
        `EXISTS (SELECT 1 FROM ${quoteIdentifier(d.table)} ${e}` +
        ` WHERE ${e}.${quoteIdentifier(d.sourceColumn)} = ${outer}.${quoteIdentifier(src.keyColumn)}${window}` +
        ` AND ${compile(node.where, { kind: 'identity', column: `${e}.${quoteIdentifier(d.targetColumn)}` })})`
      );
    }
    if (node.target.kind === 'identity') {
      const sourceObject = nextAlias('t');
      return (
        `EXISTS (SELECT 1 FROM user_relation ${e} JOIN object_ref ${sourceObject} ON ${sourceObject}.object_id=${e}.object_id` +
        ` WHERE ${sourceObject}.type_key = ${bind(utf8(node.source), 'bytea')}` +
        ` AND ${e}.relation_key = ${bind(utf8(node.relation.key), 'bytea')}` +
        ` AND ${e}.relation_version = ${bind(String(node.relation.version), 'int4')}` +
        ` AND ${e}.object_id = ${outer}.${quoteIdentifier(src.objectIdColumn)}` +
        ` AND ${active(e, 'starts_at', 'expires_at')}` +
        ` AND ${compile(node.where, { kind: 'identity', column: `${e}.user_id` })})`
      );
    }
    const target = registry.resource(node.target.type);
    const t = nextAlias('t');
    return (
      `EXISTS (SELECT 1 FROM relation_edge ${e} JOIN ${quoteIdentifier(target.table)} ${t}` +
      ` ON ${t}.${quoteIdentifier(target.objectIdColumn)} = ${e}.target_object` +
      ` WHERE ${e}.relation_key = ${bind(utf8(node.relation.key), 'bytea')}` +
      ` AND ${e}.relation_version = ${bind(String(node.relation.version), 'int4')}` +
      ` AND ${e}.source_object = ${outer}.${quoteIdentifier(src.objectIdColumn)}` +
      ` AND ${e}.source_type = ${bind(utf8(node.source), 'bytea')}` +
      ` AND ${e}.target_type = ${bind(utf8(node.target.type), 'bytea')}` +
      ` AND ${active(e, 'starts_at', 'expires_at')}` +
      ` AND ${compile(node.where, { kind: 'resource', alias: t, binding: target })})`
    );
  };

  const exception = (node: Extract<PlanExpr, { op: 'exception' }>, current: Scope): string => {
    if (current.kind !== 'resource')
      throw new TypeError('Record exceptions apply to the requested resource only');
    const x = nextAlias('x');
    const src = current.binding;
    const roles = node.roles.map((role) => bind(utf8(role), 'bytea'));
    const subject =
      roles.length > 0
        ? `(${x}.user_id = ${bind(node.identity, 'uuid')} OR ${x}.role_key IN (${roles.join(', ')}))`
        : `${x}.user_id = ${bind(node.identity, 'uuid')}`;
    // Emergency allows need the D3 activation contract (later task); until then they never grant.
    const purpose = node.effect === 'allow' ? ` AND ${x}.purpose = ${bind('manual', 'text')}` : '';
    return (
      `EXISTS (SELECT 1 FROM record_exception ${x}` +
      ` WHERE ${x}.object_id = ${current.alias}.${quoteIdentifier(src.objectIdColumn)}` +
      ` AND ${x}.type_key = ${bind(utf8(src.resource), 'bytea')}` +
      ` AND ${x}.permission_key = ${bind(utf8(node.permission), 'bytea')}` +
      ` AND ${x}.effect = ${bind(node.effect, 'text')}${purpose}` +
      ` AND ${x}.revoked_at IS NULL AND ${active(x, 'starts_at', 'expires_at')}` +
      ` AND ${subject})`
    );
  };

  return compile(expr, scope);
}

/**
 * Full authorization predicate for `alias`: plan validity on the database
 * statement clock, then the plan expression P.
 */
export function compileWith(
  plan: UserAuthorizedPlan,
  registry: ProductBindingRegistry,
  alias: string,
  bind: Bind,
): string {
  if (!/^[a-z]$/.test(alias)) throw new TypeError('Predicate alias must be a single letter');
  const binding = registry.resource(plan.resource);
  const counters = { e: 0, t: 0, x: 0 };
  const nextAlias = (prefix: 'e' | 't' | 'x') => `${alias}_${prefix}${++counters[prefix]}`;
  const predicate = compileExpression(
    plan.predicate,
    registry,
    { kind: 'resource', alias, binding },
    bind,
    nextAlias,
  );
  return `statement_timestamp() < ${bind(plan.validUntil, 'timestamptz')}` + ` AND ${predicate}`;
}

/** Raw-SQL form with driver positional binds ($1..$n); alias `r` unless given. */
export function compilePlan(
  plan: UserAuthorizedPlan,
  registry: ProductBindingRegistry,
  alias = 'r',
  firstIndex = 1,
): BoundPredicate {
  const parameters: unknown[] = [];
  const sql = compileWith(plan, registry, alias, (value, pgType) => {
    parameters.push(value);
    return `CAST($${firstIndex + parameters.length - 1} AS ${pgType})`;
  });
  return { sql, parameters };
}

let namedSequence = 0;
/** QueryBuilder form: process-unique named parameters so several predicates can share one query. */
export function compileNamed(
  plan: UserAuthorizedPlan,
  registry: ProductBindingRegistry,
  alias = 'r',
): { readonly sql: string; readonly parameters: Readonly<Record<string, unknown>> } {
  const prefix = `authz_${++namedSequence}_`;
  const parameters: Record<string, unknown> = {};
  let index = 0;
  const sql = compileWith(plan, registry, alias, (value, pgType) => {
    const name = `${prefix}${++index}`;
    parameters[name] = value;
    return `CAST(:${name} AS ${pgType})`;
  });
  return { sql, parameters };
}
