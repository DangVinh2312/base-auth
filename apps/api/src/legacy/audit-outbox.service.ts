import type { AuthorizationCore, IdentityId } from '@base-authorization/core';
import type { TenantTransaction } from '@base-authorization/typeorm-postgres/legacy';

export interface AuditEvent {
  /** Idempotency key for the sink; a duplicate fails the transaction. */
  readonly eventId: string;
  readonly actorId: IdentityId;
  readonly kind: string;
  readonly permission?: string;
  readonly objectId?: string;
  readonly reason?: string;
  /** Flat, non-sensitive facts only: no tokens, secrets or free-form PII. */
  readonly metadata?: Readonly<Record<string, string | number | boolean | null>>;
}

const kindPattern = /^[a-z][a-zA-Z0-9_.]{0,95}$/;
const maxMetadataBytes = 2_048;

/**
 * Appends an audit event to the tenant outbox inside the caller's transaction, stamped with the
 * authority revision. Any failure propagates, so the effect/payload of that transaction is not
 * committed or released. Delivery to an external sink is a separate worker (Task 12).
 */
export class AuditOutboxService {
  constructor(private readonly core: AuthorizationCore) {}

  async append(tx: TenantTransaction, event: AuditEvent): Promise<void> {
    const { isCanonicalUuid } = this.core;
    if (!isCanonicalUuid(event.eventId) || !isCanonicalUuid(event.actorId)) {
      throw new TypeError('Audit event and actor ids must be canonical UUIDs');
    }
    if (!kindPattern.test(event.kind)) throw new TypeError('Audit event kind is invalid');
    if (event.objectId !== undefined && !isCanonicalUuid(event.objectId)) {
      throw new TypeError('Audit object id must be a canonical UUID');
    }
    const metadata = event.metadata ?? {};
    for (const value of Object.values(metadata)) {
      if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) {
        throw new TypeError('Audit metadata must be flat scalars');
      }
    }
    const serialized = JSON.stringify(metadata);
    if (Buffer.byteLength(serialized) > maxMetadataBytes)
      throw new TypeError('Audit metadata is too large');
    await tx.manager.query(
      `INSERT INTO audit_outbox (tenant_id, event_id, actor_id, event_kind, permission_key, object_id,
         policy_revision, occurred_at, reason, safe_metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp(), $8, $9)`,
      [
        tx.tenant,
        event.eventId,
        event.actorId,
        Buffer.from(event.kind, 'utf8'),
        event.permission === undefined ? null : Buffer.from(event.permission, 'utf8'),
        event.objectId ?? null,
        tx.revision,
        event.reason ?? null,
        serialized,
      ],
    );
  }
}
