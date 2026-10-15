import {
  type AuthorizedPlan,
  type FieldKind,
  type Key,
  type PlanExpr,
} from '@base-authorization/core';
import type { ObjectLiteral, SelectQueryBuilder } from 'typeorm';
import {
  type BindingRegistry,
  compileExpression,
  compileNamed,
  compilePlan,
  keyPgTypes,
  quoteIdentifier,
  type ResourceBinding,
} from './sql-compiler.js';
import type { TenantTransaction } from './tenant-transaction.js';

export interface ListQuery {
  /** Subset of the AST on projected fields: and/or/eq/lt/lte/isNull with typed values. */
  readonly filter?: unknown;
  readonly orderBy?: string;
  readonly direction?: 'asc' | 'desc';
  readonly limit?: number;
  readonly offset?: number;
}

export type Row = Readonly<Record<string, unknown>> & { readonly key: string };

export interface Page {
  readonly items: readonly Row[];
  /** Matching rows for the same statement snapshot (window count); bigint as string. */
  readonly total: string;
}

const limits = { defaultLimit: 20, maxLimit: 100, maxOffset: 10_000, maxFilterNodes: 32 };
const orderedKinds: readonly FieldKind[] = ['integer', 'decimal', 'string', 'timestamp'];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Bounded reads through an authorized plan (list/detail/count and a QueryBuilder bridge).
 * The predicate is applied before pagination; projection is an allowlist; values are bound.
 */
export class DataGateway {
  readonly #registry: BindingRegistry;

  constructor(registry: BindingRegistry) {
    this.#registry = registry;
  }

  async list(plan: AuthorizedPlan, query: ListQuery, tx: TenantTransaction): Promise<Page> {
    const { binding, bound, where } = this.#prepare(plan, query.filter, tx);
    const limit = query.limit ?? limits.defaultLimit;
    const offset = query.offset ?? 0;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > limits.maxLimit)
      throw new TypeError(`limit must be 1-${limits.maxLimit}`);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > limits.maxOffset)
      throw new TypeError(`offset must be 0-${limits.maxOffset}`);
    const direction = query.direction ?? 'asc';
    if (direction !== 'asc' && direction !== 'desc')
      throw new TypeError('direction must be asc or desc');
    const key = `r.${quoteIdentifier(binding.keyColumn)}`;
    const order =
      query.orderBy === undefined
        ? `${key} ${direction}`
        : `${this.#projectedColumn(binding, query.orderBy)} ${direction}, ${key} ${direction}`;
    const parameters = [...bound.parameters, limit, offset];
    const rows = await tx.manager.query<Record<string, unknown>[]>(
      `SELECT ${this.#projection(binding)}, count(*) OVER () AS "$total" FROM ${quoteIdentifier(binding.table)} r` +
        ` WHERE ${bound.sql}${where} ORDER BY ${order}` +
        ` LIMIT CAST($${parameters.length - 1} AS int4) OFFSET CAST($${parameters.length} AS int4)`,
      parameters,
    );
    const total =
      rows.length > 0
        ? String(rows[0]!.$total)
        : offset === 0
          ? '0'
          : await this.count(plan, query, tx);
    const items = rows.map((row) => {
      const { $total, ...fields } = row;
      void $total;
      return fields as Row;
    });
    return { items, total };
  }

  async count(
    plan: AuthorizedPlan,
    query: Pick<ListQuery, 'filter'>,
    tx: TenantTransaction,
  ): Promise<string> {
    const { binding, bound, where } = this.#prepare(plan, query.filter, tx);
    const rows = await tx.manager.query<{ n: string }[]>(
      `SELECT count(*)::text AS n FROM ${quoteIdentifier(binding.table)} r WHERE ${bound.sql}${where}`,
      [...bound.parameters],
    );
    return rows[0]?.n ?? '0';
  }

  /** Same response for absent, foreign and not-visible records: null. */
  async detail(plan: AuthorizedPlan, key: Key, tx: TenantTransaction): Promise<Row | null> {
    const { binding, bound } = this.#prepare(plan, undefined, tx);
    const declared = this.#registry.declarations.resources[plan.resource]!;
    if (key.kind !== declared.keyKind)
      throw new TypeError(`${plan.resource} keys are ${declared.keyKind}`);
    const value = this.#registry.core.parseKey(key.kind, key.value).value;
    const parameters = [...bound.parameters, value];
    const rows = await tx.manager.query<Row[]>(
      `SELECT ${this.#projection(binding)} FROM ${quoteIdentifier(binding.table)} r WHERE ${bound.sql}` +
        ` AND r.${quoteIdentifier(binding.keyColumn)} = CAST($${parameters.length} AS ${keyPgTypes[key.kind]}) LIMIT 1`,
      parameters,
    );
    return rows[0] ?? null;
  }

  /**
   * QueryBuilder over an authorized derived table exposing only `key` and projected fields.
   * Handler `.where()`/`.orWhere()` act on that table, so they cannot remove the predicate.
   */
  queryBuilder(
    plan: AuthorizedPlan,
    tx: TenantTransaction,
    alias: string,
  ): SelectQueryBuilder<ObjectLiteral> {
    this.#checkTransaction(plan, tx);
    return tx.manager.createQueryBuilder().from(this.subQuery(plan), alias);
  }

  /** Authorized derived table for joins: nested resources only through their own plan. */
  subQuery(
    plan: AuthorizedPlan,
  ): (qb: SelectQueryBuilder<ObjectLiteral>) => SelectQueryBuilder<ObjectLiteral> {
    const binding = this.#registry.resource(plan.resource);
    const named = compileNamed(plan, this.#registry, 'r');
    return (qb) =>
      qb
        .select(this.#projection(binding))
        .from(binding.table, 'r')
        .where(named.sql, named.parameters);
  }

  #checkTransaction(plan: AuthorizedPlan, tx: TenantTransaction): void {
    if (plan.tenant !== tx.tenant)
      throw new Error('Plan tenant does not match the transaction tenant');
  }

  #prepare(plan: AuthorizedPlan, filter: unknown, tx: TenantTransaction) {
    this.#checkTransaction(plan, tx);
    const binding = this.#registry.resource(plan.resource);
    const bound = compilePlan(plan, this.#registry);
    if (filter === undefined) return { binding, bound, where: '' };
    const parameters = [...bound.parameters];
    const sql = compileExpression(
      this.#filter(binding, plan.resource, filter),
      this.#registry,
      { kind: 'resource', alias: 'r', binding },
      (value, pgType) => {
        parameters.push(value);
        return `CAST($${parameters.length} AS ${pgType})`;
      },
      () => {
        throw new TypeError('Filters cannot traverse relations');
      },
    );
    // Parenthesized and ANDed: an OR inside the filter cannot escape the authorization predicate.
    return { binding, bound: { sql: bound.sql, parameters }, where: ` AND (${sql})` };
  }

  #filter(binding: ResourceBinding, resource: string, input: unknown): PlanExpr {
    const fields = this.#registry.declarations.resources[resource]!.fields;
    let nodes = 0;

    const visit = (node: unknown): PlanExpr => {
      if (++nodes > limits.maxFilterNodes) throw new TypeError('Filter is too large');
      if (!isRecord(node)) throw new TypeError('Filter node must be an object');
      if (
        (node.op === 'and' || node.op === 'or') &&
        Array.isArray(node.args) &&
        node.args.length > 0
      ) {
        return { op: node.op, args: node.args.map(visit) };
      }
      const field =
        typeof node.field === 'string' && binding.projection.includes(node.field)
          ? fields[node.field]
          : undefined;
      if (!field) throw new TypeError(`Filter field ${String(node.field)} is not readable`);
      if (node.op === 'isNull') return { op: 'isNull', field: node.field as string };
      if (
        node.op === 'eq' ||
        ((node.op === 'lt' || node.op === 'lte') && orderedKinds.includes(field.kind))
      ) {
        const value = this.#registry.core.normalizeValue(field.kind, node.value);
        if (value === undefined)
          throw new TypeError(`Filter value for ${String(node.field)} must be a ${field.kind}`);
        return { op: node.op, field: node.field as string, kind: field.kind, value };
      }
      throw new TypeError(`Unsupported filter operator ${JSON.stringify(node.op)}`);
    };

    return visit(input);
  }

  #projectedColumn(binding: ResourceBinding, field: string): string {
    if (!binding.projection.includes(field)) throw new TypeError(`Field ${field} is not readable`);
    return `r.${quoteIdentifier(binding.columns[field]!)}`;
  }

  /** key + allowlisted fields; integers and timestamps as canonical text (no JS number, no Date). */
  #projection(binding: ResourceBinding): string {
    const declared = this.#registry.declarations.resources[binding.resource]!;
    const keyColumn = `r.${quoteIdentifier(binding.keyColumn)}`;
    const key = declared.keyKind === 'integer' ? `CAST(${keyColumn} AS text)` : keyColumn;
    const fields = binding.projection.map((field) => {
      const column = this.#projectedColumn(binding, field);
      const kind = declared.fields[field]!.kind;
      const expression =
        kind === 'integer' || kind === 'decimal'
          ? `CAST(${column} AS text)`
          : kind === 'timestamp'
            ? `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
            : column;
      return `${expression} AS "${field}"`;
    });
    return [`${key} AS "key"`, ...fields].join(', ');
  }
}
