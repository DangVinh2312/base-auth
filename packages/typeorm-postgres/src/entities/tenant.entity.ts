import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * Column mappings of one tenant database. Composite FKs, CHECKs and indexes live in the
 * handwritten migration; `synchronize` is never enabled. bigint columns stay strings.
 */

type Lifecycle = 'active' | 'deprecated' | 'retired';
type KeyKind = 'integer' | 'uuid' | 'string';
type Effect = 'allow' | 'deny';

const tenantId = () => PrimaryColumn({ name: 'tenant_id', type: 'uuid' });
const pkUuid = (name: string) => PrimaryColumn({ name, type: 'uuid' });
const pkBytes = (name: string) => PrimaryColumn({ name, type: 'bytea' });
const uuid = (name: string, nullable = false) => Column({ name, type: 'uuid', nullable });
const bytes = (name: string, nullable = false) => Column({ name, type: 'bytea', nullable });
const text = (name: string, length: number, nullable = false) =>
  Column({ name, type: 'varchar', length, nullable });
const time = (name: string, nullable = false) =>
  Column({ name, type: 'timestamptz', precision: 6, nullable });

@Entity({ name: 'tenant_anchor' })
export class TenantAnchor {
  @tenantId() tenantId!: string;
}

@Entity({ name: 'authz_fence' })
export class AuthzFence {
  @tenantId() tenantId!: string;
  @Column({ type: 'bigint' }) revision!: string;
  @bytes('manifest_hash') manifestHash!: Buffer;
  @Column({ name: 'release_sequence', type: 'bigint' }) releaseSequence!: string;
  @Column({ name: 'min_runtime_capability', type: 'smallint' }) minRuntimeCapability!: number;
}

@Entity({ name: 'membership' })
export class Membership {
  @tenantId() tenantId!: string;
  @pkUuid('identity_id') identityId!: string;
  @text('state', 16) state!: 'active' | 'suspended';
  @Column({ name: 'authority_level', type: 'smallint' }) authorityLevel!: number;
  @Column({ type: 'boolean' }) protected!: boolean;
}

@Entity({ name: 'resource_type' })
export class ResourceType {
  @tenantId() tenantId!: string;
  @pkBytes('type_key') typeKey!: Buffer;
  @text('key_kind', 16) keyKind!: KeyKind;
  @bytes('binding_key') bindingKey!: Buffer;
}

@Entity({ name: 'permission_policy' })
export class PermissionPolicy {
  @tenantId() tenantId!: string;
  @pkBytes('policy_key') policyKey!: Buffer;
  @PrimaryColumn({ name: 'policy_version', type: 'integer' }) policyVersion!: number;
  @bytes('definition_hash') definitionHash!: Buffer;
  @Column({ type: 'jsonb' }) definition!: unknown;
  @text('lifecycle', 16) lifecycle!: Lifecycle;
}

@Entity({ name: 'permission_catalog' })
export class PermissionCatalog {
  @tenantId() tenantId!: string;
  @pkBytes('permission_key') permissionKey!: Buffer;
  @bytes('type_key') typeKey!: Buffer;
  @bytes('action_key') actionKey!: Buffer;
  @bytes('policy_key') policyKey!: Buffer;
  @Column({ name: 'policy_version', type: 'integer' }) policyVersion!: number;
  @text('lifecycle', 16) lifecycle!: Lifecycle;
  /** NULL only on rows that predate migration 003 until a release backfills them. */
  @text('boundary_requirement', 16, true) boundaryRequirement!: 'required' | 'optional' | null;
}

@Entity({ name: 'scope_template' })
export class ScopeTemplate {
  @tenantId() tenantId!: string;
  @pkBytes('template_key') templateKey!: Buffer;
  @PrimaryColumn({ type: 'integer' }) version!: number;
  @bytes('definition_hash') definitionHash!: Buffer;
}

@Entity({ name: 'role_definition' })
export class RoleDefinition {
  @tenantId() tenantId!: string;
  @pkBytes('role_key') roleKey!: Buffer;
  @text('managed_by', 16) managedBy!: 'code' | 'tenant';
  @Column({ name: 'authority_level', type: 'smallint' }) authorityLevel!: number;
  @text('label', 120) label!: string;
}

@Entity({ name: 'member_role' })
export class MemberRole {
  @tenantId() tenantId!: string;
  @pkUuid('identity_id') identityId!: string;
  @pkBytes('role_key') roleKey!: Buffer;
}

@Entity({ name: 'policy_rule' })
export class PolicyRule {
  @tenantId() tenantId!: string;
  @pkUuid('rule_id') ruleId!: string;
  @bytes('permission_key') permissionKey!: Buffer;
  @uuid('identity_id', true) identityId!: string | null;
  @bytes('role_key', true) roleKey!: Buffer | null;
  @text('effect', 8) effect!: Effect;
  @bytes('template_key') templateKey!: Buffer;
  @Column({ name: 'template_version', type: 'integer' }) templateVersion!: number;
  @Column({ type: 'jsonb' }) parameters!: unknown;
  @text('managed_by', 16) managedBy!: 'code' | 'tenant';
}

@Entity({ name: 'object_ref' })
export class ObjectRef {
  @tenantId() tenantId!: string;
  @pkUuid('object_id') objectId!: string;
  @bytes('type_key') typeKey!: Buffer;
  @text('key_kind', 16) keyKind!: KeyKind;
  @bytes('key_bytes') keyBytes!: Buffer;
}

@Entity({ name: 'record_exception' })
export class RecordException {
  @tenantId() tenantId!: string;
  @pkUuid('exception_id') exceptionId!: string;
  @uuid('object_id') objectId!: string;
  @bytes('type_key') typeKey!: Buffer;
  @bytes('permission_key') permissionKey!: Buffer;
  @uuid('identity_id', true) identityId!: string | null;
  @bytes('role_key', true) roleKey!: Buffer | null;
  @text('effect', 8) effect!: Effect;
  @text('purpose', 16) purpose!: 'manual' | 'emergency';
  @time('starts_at') startsAt!: Date;
  @time('expires_at', true) expiresAt!: Date | null;
  @text('reason', 1000) reason!: string;
  @uuid('issued_by') issuedBy!: string;
  @time('revoked_at', true) revokedAt!: Date | null;
}

@Entity({ name: 'resource_relation_definition' })
export class ResourceRelationDefinition {
  @tenantId() tenantId!: string;
  @pkBytes('relation_key') relationKey!: Buffer;
  @PrimaryColumn({ name: 'relation_version', type: 'integer' }) relationVersion!: number;
  @bytes('source_type') sourceType!: Buffer;
  @bytes('target_type') targetType!: Buffer;
  @text('binding_kind', 16) bindingKind!: 'edgeStore' | 'domain';
  @bytes('binding_key') bindingKey!: Buffer;
  @bytes('definition_hash') definitionHash!: Buffer;
  @text('lifecycle', 16) lifecycle!: Lifecycle;
}

@Entity({ name: 'relation_edge' })
export class RelationEdge {
  @tenantId() tenantId!: string;
  @pkBytes('relation_key') relationKey!: Buffer;
  @PrimaryColumn({ name: 'relation_version', type: 'integer' }) relationVersion!: number;
  @pkUuid('source_object') sourceObject!: string;
  @bytes('source_type') sourceType!: Buffer;
  @pkUuid('target_object') targetObject!: string;
  @bytes('target_type') targetType!: Buffer;
  @time('starts_at') startsAt!: Date;
  @time('expires_at', true) expiresAt!: Date | null;
  @bytes('seed_owner', true) seedOwner!: Buffer | null;
  @bytes('seed_key', true) seedKey!: Buffer | null;
}

@Entity({ name: 'identity_relation' })
export class IdentityRelation {
  @tenantId() tenantId!: string;
  @pkBytes('relation_key') relationKey!: Buffer;
  @PrimaryColumn({ name: 'relation_version', type: 'integer' }) relationVersion!: number;
  @pkUuid('object_id') objectId!: string;
  @pkUuid('identity_id') identityId!: string;
  @time('starts_at') startsAt!: Date;
  @time('expires_at', true) expiresAt!: Date | null;
}

@Entity({ name: 'permission_boundary' })
export class PermissionBoundary {
  @tenantId() tenantId!: string;
  @pkBytes('boundary_key') boundaryKey!: Buffer;
  @PrimaryColumn({ name: 'boundary_version', type: 'integer' }) boundaryVersion!: number;
  @bytes('definition_hash') definitionHash!: Buffer;
  @Column({ type: 'jsonb' }) definition!: unknown;
  @text('lifecycle', 16) lifecycle!: Lifecycle;
}

@Entity({ name: 'permission_boundary_entry' })
export class PermissionBoundaryEntry {
  @tenantId() tenantId!: string;
  @pkBytes('boundary_key') boundaryKey!: Buffer;
  @PrimaryColumn({ name: 'boundary_version', type: 'integer' }) boundaryVersion!: number;
  @pkBytes('permission_key') permissionKey!: Buffer;
  @Column({ type: 'jsonb' }) definition!: unknown;
}

@Entity({ name: 'member_permission_boundary' })
export class MemberPermissionBoundary {
  @tenantId() tenantId!: string;
  @pkUuid('identity_id') identityId!: string;
  @pkBytes('permission_key') permissionKey!: Buffer;
  @bytes('boundary_key') boundaryKey!: Buffer;
  @Column({ name: 'boundary_version', type: 'integer' }) boundaryVersion!: number;
  @bytes('seed_owner', true) seedOwner!: Buffer | null;
}

@Entity({ name: 'audit_outbox' })
export class AuditOutbox {
  @tenantId() tenantId!: string;
  @pkUuid('event_id') eventId!: string;
  @uuid('actor_id') actorId!: string;
  @bytes('event_kind') eventKind!: Buffer;
  @bytes('permission_key', true) permissionKey!: Buffer | null;
  @uuid('object_id', true) objectId!: string | null;
  @Column({ name: 'policy_revision', type: 'bigint' }) policyRevision!: string;
  @time('occurred_at') occurredAt!: Date;
  @text('reason', 1000, true) reason!: string | null;
  @Column({ name: 'safe_metadata', type: 'jsonb' }) safeMetadata!: unknown;
  @time('delivered_at', true) deliveredAt!: Date | null;
}

export const tenantEntities = [
  TenantAnchor,
  AuthzFence,
  Membership,
  ResourceType,
  PermissionPolicy,
  PermissionCatalog,
  ScopeTemplate,
  RoleDefinition,
  MemberRole,
  PolicyRule,
  ObjectRef,
  RecordException,
  ResourceRelationDefinition,
  RelationEdge,
  IdentityRelation,
  PermissionBoundary,
  PermissionBoundaryEntry,
  MemberPermissionBoundary,
  AuditOutbox,
];
