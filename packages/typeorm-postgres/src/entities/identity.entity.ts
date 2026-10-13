import { Column, Entity, PrimaryColumn } from 'typeorm';

/** Column mappings of the identity database. Constraints live in the handwritten migration. */

@Entity({ name: 'identity_record' })
export class IdentityRecord {
  @PrimaryColumn({ type: 'uuid' }) id!: string;
  @Column({ type: 'varchar', length: 16 }) state!: 'active' | 'disabled';
  /** bigint stays a string; never coerce through JS number. */
  @Column({ type: 'bigint' }) revision!: string;
  @Column({ name: 'created_at', type: 'timestamptz', precision: 6 }) createdAt!: Date;
}

@Entity({ name: 'federated_identity' })
export class FederatedIdentity {
  @PrimaryColumn({ type: 'bytea' }) issuer!: Buffer;
  @PrimaryColumn({ type: 'bytea' }) subject!: Buffer;
  @Column({ name: 'identity_id', type: 'uuid' }) identityId!: string;
}

@Entity({ name: 'auth_session' })
export class AuthSession {
  @PrimaryColumn({ name: 'token_hash', type: 'bytea' }) tokenHash!: Buffer;
  @Column({ name: 'identity_id', type: 'uuid' }) identityId!: string;
  @Column({ type: 'smallint' }) assurance!: number;
  @Column({ name: 'expires_at', type: 'timestamptz', precision: 6 }) expiresAt!: Date;
  @Column({ name: 'revoked_at', type: 'timestamptz', precision: 6, nullable: true })
  revokedAt!: Date | null;
  @Column({ name: 'created_at', type: 'timestamptz', precision: 6 }) createdAt!: Date;
}

@Entity({ name: 'tenant_directory' })
export class TenantDirectoryEntry {
  @PrimaryColumn({ type: 'uuid' }) id!: string;
  @Column({ name: 'display_label', type: 'varchar', length: 120 }) displayLabel!: string;
  @Column({ name: 'route_ref', type: 'bytea' }) routeRef!: Buffer;
  @Column({ type: 'varchar', length: 16 }) state!: 'active' | 'disabled';
}

export const identityEntities = [
  IdentityRecord,
  FederatedIdentity,
  AuthSession,
  TenantDirectoryEntry,
];
