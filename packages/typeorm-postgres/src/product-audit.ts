import type { IdentityId, KeyKind } from '@base-authorization/core';
import type { ProductTransaction } from './product-transaction.js';

/**
 * `actor_id` of offline commands (manifest sync, Root and enrollment CLI): no product user acts;
 * the operator/approver identity lives in the referenced approval record, never in the target.
 */
export const PRODUCT_OFFLINE_ACTOR = '00000000-0000-4000-8000-000000000001' as IdentityId;
type UserTarget = { readonly userId: string };
/** Requested record key of an access; metadata keeps `key` only for uuid/integer kinds. */
type RequestedKey = {
  readonly resource: string;
  readonly keyKind: KeyKind;
  readonly key: string;
};
/** Root marker, written only from the verified session kind through typed input (spec 6.5). */
type RootOutcome = { readonly principalKind: 'root'; readonly outcome: 'ok' | 'absent' };

export type ProductIdentityAuditKind =
  | 'identity.login'
  | 'identity.logout'
  | 'identity.logout-all'
  | 'identity.activation'
  | 'identity.password-reset'
  | 'identity.reauthenticate'
  | 'identity.password-change'
  | 'identity.oidc-link'
  | 'identity.oidc-activation'
  | 'identity.oidc-login'
  | 'identity.oidc-reauth'
  | 'identity.oidc-unlink';
/**
 * Typed audit events (ADR 0009). `access.*` records an authorization decision (obligation audit@1);
 * every other kind records an effect. No free-form metadata: only the fields below are written.
 */
export type ProductAuditEvent =
  | { readonly kind: `access.${string}`; readonly actor: string; readonly permission: string }
  | ({
      readonly kind: `access.${string}`;
      readonly actor: string;
      readonly permission: string;
      /** Detail only: the requested key, ok or absent; never a made-up target. */
      readonly target?: RequestedKey;
    } & RootOutcome)
  | {
      readonly kind: 'data.update';
      readonly actor: string;
      readonly permission: string;
      readonly target: RequestedKey & { readonly objectId: string };
    }
  | {
      readonly kind: 'data.update';
      readonly actor: string;
      readonly permission: string;
      readonly principalKind: 'root';
      readonly outcome: 'ok';
      readonly target: RequestedKey & { readonly objectId: string };
    }
  | {
      readonly kind: 'data.update';
      readonly actor: string;
      readonly permission: string;
      readonly principalKind: 'root';
      readonly outcome: 'absent';
      readonly target: RequestedKey;
    }
  | {
      readonly kind: 'account.suspend';
      readonly actor: string;
      readonly permission: string;
      readonly target: UserTarget;
    }
  | ({
      readonly kind: 'account.suspend';
      readonly actor: string;
      readonly permission: string;
      readonly target: UserTarget;
    } & RootOutcome)
  | { readonly kind: ProductIdentityAuditKind; readonly actor: string }
  | {
      readonly kind: 'identity.enroll' | 'identity.invite';
      readonly actor: string;
      readonly target: UserTarget;
      readonly method: 'local' | 'oidc';
    }
  | {
      /** Offline maintenance; counts only, no session or user identifiers. */
      readonly kind: 'identity.session-purge';
      readonly actor: string;
      readonly deleted: string;
      readonly retentionDays: string;
    }
  | {
      readonly kind: 'manifest.sync';
      readonly actor: string;
      readonly sequence: string;
      readonly hash: string;
      /** Revision the reconciler publishes in this transaction. */
      readonly publishedRevision: string;
    }
  | {
      readonly kind: 'root.bootstrap';
      readonly actor: string;
      readonly target: UserTarget;
      readonly operationId: string;
      readonly method: 'local' | 'oidc';
    }
  | {
      readonly kind: 'root.reissue';
      readonly actor: string;
      readonly target: UserTarget;
      readonly method: 'local' | 'oidc';
    }
  | {
      readonly kind: 'root.revoke';
      readonly actor: string;
      readonly target: UserTarget;
      readonly operationId: string;
      readonly approval: string;
      /** Validated offline operator input; stored in its own column, never in metadata. */
      readonly reason: string;
    };

/** Revision committed by this transaction: the runner bumps revoke/admin/bootstrap by one. */
function resultingRevision(tx: ProductTransaction, event: ProductAuditEvent): string {
  if (event.kind === 'manifest.sync') return event.publishedRevision;
  switch (tx.mode) {
    case 'write':
    case 'identity':
      return tx.revision;
    case 'revoke':
    case 'admin':
    case 'bootstrap':
      return String(BigInt(tx.revision) + 1n);
    default:
      throw new Error(`No resulting revision for ${event.kind} in ${tx.mode} mode`);
  }
}

/**
 * Appends one event in the caller's transaction, so effect and audit commit or roll back together.
 * `policy_revision` is always the revision the transaction evaluated (fenced `tx.revision`).
 */
export async function appendProductAudit(
  tx: ProductTransaction,
  event: ProductAuditEvent,
): Promise<void> {
  const metadata: Record<string, string> = {};
  let permission: string | null = null;
  let reason: string | null = null;
  let objectId: string | null = null;
  if ('permission' in event) permission = event.permission;
  if ('target' in event && event.target && 'userId' in event.target)
    metadata.targetUserId = event.target.userId;
  if (!event.kind.startsWith('access.')) metadata.resultingRevision = resultingRevision(tx, event);
  if ('principalKind' in event) {
    metadata.principalKind = event.principalKind;
    metadata.outcome = event.outcome;
  }
  if ('target' in event && event.target && 'keyKind' in event.target) {
    metadata.resource = event.target.resource;
    metadata.keyKind = event.target.keyKind;
    if (event.target.keyKind !== 'string') metadata.key = event.target.key;
    if ('objectId' in event.target) objectId = event.target.objectId;
  }
  switch (event.kind) {
    case 'identity.enroll':
    case 'identity.invite':
    case 'root.reissue':
      metadata.method = event.method;
      break;
    case 'identity.session-purge':
      Object.assign(metadata, { deleted: event.deleted, retentionDays: event.retentionDays });
      break;
    case 'manifest.sync':
      Object.assign(metadata, { sequence: event.sequence, hash: event.hash });
      break;
    case 'root.bootstrap':
      Object.assign(metadata, { operationId: event.operationId, method: event.method });
      break;
    case 'root.revoke':
      Object.assign(metadata, { operationId: event.operationId, approval: event.approval });
      reason = event.reason;
      break;
  }
  await tx.manager.query(
    `INSERT INTO audit_outbox(event_id,actor_id,event_kind,permission_key,object_id,policy_revision,occurred_at,reason,safe_metadata) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,statement_timestamp(),$6,$7)`,
    [
      event.actor,
      Buffer.from(event.kind, 'utf8'),
      permission === null ? null : Buffer.from(permission, 'utf8'),
      objectId,
      tx.revision,
      reason,
      JSON.stringify(metadata),
    ],
  );
}
