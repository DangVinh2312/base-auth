import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Identity/control-plane schema (spec section 6): identities, federation, sessions, tenant directory. */
export class IdentityInitial1791849600000 implements MigrationInterface {
  name = 'IdentityInitial1791849600000';

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE identity_record (
        id uuid PRIMARY KEY,
        state varchar(16) NOT NULL CONSTRAINT ck_identity_state CHECK (state IN ('active', 'disabled')),
        revision bigint NOT NULL DEFAULT 1 CONSTRAINT ck_identity_revision CHECK (revision > 0),
        created_at timestamptz(6) NOT NULL
      );

      CREATE TABLE federated_identity (
        issuer bytea NOT NULL CONSTRAINT ck_federation_issuer CHECK (octet_length(issuer) BETWEEN 1 AND 255),
        subject bytea NOT NULL CONSTRAINT ck_federation_subject CHECK (octet_length(subject) BETWEEN 1 AND 255),
        identity_id uuid NOT NULL CONSTRAINT fk_federation_identity REFERENCES identity_record (id),
        PRIMARY KEY (issuer, subject)
      );
      CREATE INDEX ix_federation_identity ON federated_identity (identity_id);

      CREATE TABLE auth_session (
        token_hash bytea PRIMARY KEY CONSTRAINT ck_session_token_hash CHECK (octet_length(token_hash) = 32),
        identity_id uuid NOT NULL CONSTRAINT fk_session_identity REFERENCES identity_record (id),
        assurance smallint NOT NULL CONSTRAINT ck_session_assurance CHECK (assurance BETWEEN 0 AND 10),
        expires_at timestamptz(6) NOT NULL,
        revoked_at timestamptz(6),
        created_at timestamptz(6) NOT NULL
      );
      CREATE INDEX ix_session_identity ON auth_session (identity_id, revoked_at);
      CREATE INDEX ix_session_expiry ON auth_session (expires_at);

      CREATE TABLE tenant_directory (
        id uuid PRIMARY KEY,
        display_label varchar(120) NOT NULL,
        route_ref bytea NOT NULL CONSTRAINT uq_directory_route UNIQUE
          CONSTRAINT ck_directory_route CHECK (octet_length(route_ref) BETWEEN 1 AND 128),
        state varchar(16) NOT NULL CONSTRAINT ck_directory_state CHECK (state IN ('active', 'disabled'))
      );
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'DROP TABLE tenant_directory, auth_session, federated_identity, identity_record',
    );
  }
}
