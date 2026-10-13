import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Bounded byte key, the PostgreSQL mapping of VARBINARY(n) in spec section 6. */
const key = (column: string, max: number, nullable = false) =>
  `${column} bytea ${nullable ? '' : 'NOT NULL '}CONSTRAINT ck_${column}_length CHECK (octet_length(${column}) BETWEEN 1 AND ${max})`;
const hash = (column: string) =>
  `${column} bytea NOT NULL CONSTRAINT ck_${column}_length CHECK (octet_length(${column}) = 32)`;
const lifecycle = `lifecycle varchar(16) NOT NULL CONSTRAINT ck_lifecycle CHECK (lifecycle IN ('active', 'deprecated', 'retired'))`;
const keyKind = `key_kind varchar(16) NOT NULL CONSTRAINT ck_key_kind CHECK (key_kind IN ('integer', 'uuid', 'string'))`;
const managedBy = `managed_by varchar(16) NOT NULL CONSTRAINT ck_managed_by CHECK (managed_by IN ('code', 'tenant'))`;
const anchor = `tenant_id uuid NOT NULL CONSTRAINT fk_tenant_anchor REFERENCES tenant_anchor (tenant_id)`;
const oneSubject = `CONSTRAINT ck_one_subject CHECK ((identity_id IS NOT NULL AND role_key IS NULL) OR (identity_id IS NULL AND role_key IS NOT NULL))`;

/**
 * Tenant authority schema (spec section 6) for one tenant database.
 * The anchor row is inserted by provisioning; the single-row index fixes one tenant per database.
 * PostgreSQL does not index referencing columns, so every FK without a covering prefix gets one.
 */
export class TenantInitial1791849600000 implements MigrationInterface {
  name = 'TenantInitial1791849600000';

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE tenant_anchor (tenant_id uuid PRIMARY KEY);
      CREATE UNIQUE INDEX uq_tenant_anchor_single ON tenant_anchor ((true));

      CREATE TABLE authz_fence (
        tenant_id uuid PRIMARY KEY CONSTRAINT fk_tenant_anchor REFERENCES tenant_anchor (tenant_id),
        revision bigint NOT NULL DEFAULT 1 CONSTRAINT ck_fence_revision CHECK (revision > 0),
        ${hash('manifest_hash')},
        release_sequence bigint NOT NULL DEFAULT 0 CONSTRAINT ck_fence_release CHECK (release_sequence >= 0)
      );

      CREATE TABLE membership (
        ${anchor},
        identity_id uuid NOT NULL,
        state varchar(16) NOT NULL CONSTRAINT ck_membership_state CHECK (state IN ('active', 'suspended')),
        authority_level smallint NOT NULL DEFAULT 0
          CONSTRAINT ck_membership_level CHECK (authority_level BETWEEN 0 AND 1000),
        protected boolean NOT NULL DEFAULT false,
        PRIMARY KEY (tenant_id, identity_id)
      );

      CREATE TABLE resource_type (
        ${anchor},
        ${key('type_key', 96)},
        ${keyKind},
        ${key('binding_key', 128)},
        PRIMARY KEY (tenant_id, type_key)
      );

      CREATE TABLE permission_policy (
        ${anchor},
        ${key('policy_key', 128)},
        policy_version integer NOT NULL CONSTRAINT ck_policy_version CHECK (policy_version > 0),
        ${hash('definition_hash')},
        definition jsonb NOT NULL,
        ${lifecycle},
        PRIMARY KEY (tenant_id, policy_key, policy_version)
      );

      CREATE TABLE permission_catalog (
        tenant_id uuid NOT NULL,
        ${key('permission_key', 160)},
        ${key('type_key', 96)},
        ${key('action_key', 64)},
        ${key('policy_key', 128)},
        policy_version integer NOT NULL,
        ${lifecycle},
        PRIMARY KEY (tenant_id, permission_key),
        CONSTRAINT uq_permission_action UNIQUE (tenant_id, type_key, action_key),
        CONSTRAINT uq_permission_type UNIQUE (tenant_id, permission_key, type_key),
        CONSTRAINT fk_permission_type FOREIGN KEY (tenant_id, type_key)
          REFERENCES resource_type (tenant_id, type_key),
        CONSTRAINT fk_permission_policy FOREIGN KEY (tenant_id, policy_key, policy_version)
          REFERENCES permission_policy (tenant_id, policy_key, policy_version)
      );
      CREATE INDEX ix_permission_policy ON permission_catalog (tenant_id, policy_key, policy_version);

      CREATE TABLE scope_template (
        ${anchor},
        ${key('template_key', 128)},
        version integer NOT NULL CONSTRAINT ck_template_version CHECK (version > 0),
        ${hash('definition_hash')},
        PRIMARY KEY (tenant_id, template_key, version)
      );

      CREATE TABLE role_definition (
        ${anchor},
        ${key('role_key', 96)},
        ${managedBy},
        authority_level smallint NOT NULL CONSTRAINT ck_role_level CHECK (authority_level BETWEEN 0 AND 1000),
        label varchar(120) NOT NULL,
        PRIMARY KEY (tenant_id, role_key)
      );

      CREATE TABLE member_role (
        tenant_id uuid NOT NULL,
        identity_id uuid NOT NULL,
        ${key('role_key', 96)},
        PRIMARY KEY (tenant_id, identity_id, role_key),
        CONSTRAINT fk_member_role_membership FOREIGN KEY (tenant_id, identity_id)
          REFERENCES membership (tenant_id, identity_id),
        CONSTRAINT fk_member_role_role FOREIGN KEY (tenant_id, role_key)
          REFERENCES role_definition (tenant_id, role_key)
      );
      CREATE INDEX ix_role_members ON member_role (tenant_id, role_key, identity_id);

      CREATE TABLE policy_rule (
        tenant_id uuid NOT NULL,
        rule_id uuid NOT NULL,
        ${key('permission_key', 160)},
        identity_id uuid,
        ${key('role_key', 96, true)},
        effect varchar(8) NOT NULL CONSTRAINT ck_effect CHECK (effect IN ('allow', 'deny')),
        ${key('template_key', 128)},
        template_version integer NOT NULL,
        parameters jsonb NOT NULL,
        ${managedBy},
        PRIMARY KEY (tenant_id, rule_id),
        ${oneSubject},
        CONSTRAINT fk_rule_permission FOREIGN KEY (tenant_id, permission_key)
          REFERENCES permission_catalog (tenant_id, permission_key),
        CONSTRAINT fk_rule_membership FOREIGN KEY (tenant_id, identity_id)
          REFERENCES membership (tenant_id, identity_id),
        CONSTRAINT fk_rule_role FOREIGN KEY (tenant_id, role_key)
          REFERENCES role_definition (tenant_id, role_key),
        CONSTRAINT fk_rule_template FOREIGN KEY (tenant_id, template_key, template_version)
          REFERENCES scope_template (tenant_id, template_key, version)
      );
      CREATE INDEX ix_rule_identity ON policy_rule (tenant_id, permission_key, identity_id, effect);
      CREATE INDEX ix_rule_role ON policy_rule (tenant_id, permission_key, role_key, effect);
      CREATE INDEX ix_rule_membership ON policy_rule (tenant_id, identity_id);
      CREATE INDEX ix_rule_role_definition ON policy_rule (tenant_id, role_key);
      CREATE INDEX ix_rule_template ON policy_rule (tenant_id, template_key, template_version);

      CREATE TABLE object_ref (
        tenant_id uuid NOT NULL,
        object_id uuid NOT NULL,
        ${key('type_key', 96)},
        ${keyKind},
        ${key('key_bytes', 256)},
        PRIMARY KEY (tenant_id, object_id),
        CONSTRAINT uq_object_key UNIQUE (tenant_id, type_key, key_kind, key_bytes),
        CONSTRAINT uq_object_type UNIQUE (tenant_id, object_id, type_key),
        CONSTRAINT fk_object_type FOREIGN KEY (tenant_id, type_key)
          REFERENCES resource_type (tenant_id, type_key)
      );

      CREATE TABLE record_exception (
        tenant_id uuid NOT NULL,
        exception_id uuid NOT NULL,
        object_id uuid NOT NULL,
        ${key('type_key', 96)},
        ${key('permission_key', 160)},
        identity_id uuid,
        ${key('role_key', 96, true)},
        effect varchar(8) NOT NULL CONSTRAINT ck_effect CHECK (effect IN ('allow', 'deny')),
        purpose varchar(16) NOT NULL CONSTRAINT ck_exception_purpose CHECK (purpose IN ('manual', 'emergency')),
        starts_at timestamptz(6) NOT NULL,
        expires_at timestamptz(6),
        reason varchar(1000) NOT NULL CONSTRAINT ck_exception_reason CHECK (char_length(btrim(reason)) > 0),
        issued_by uuid NOT NULL,
        revoked_at timestamptz(6),
        PRIMARY KEY (tenant_id, exception_id),
        ${oneSubject},
        CONSTRAINT ck_exception_interval CHECK (expires_at IS NULL OR expires_at > starts_at),
        CONSTRAINT ck_exception_emergency CHECK (
          purpose <> 'emergency' OR (expires_at IS NOT NULL AND effect = 'allow' AND identity_id IS NOT NULL)
        ),
        CONSTRAINT fk_exception_object FOREIGN KEY (tenant_id, object_id, type_key)
          REFERENCES object_ref (tenant_id, object_id, type_key) ON DELETE CASCADE,
        CONSTRAINT fk_exception_permission FOREIGN KEY (tenant_id, permission_key, type_key)
          REFERENCES permission_catalog (tenant_id, permission_key, type_key),
        CONSTRAINT fk_exception_membership FOREIGN KEY (tenant_id, identity_id)
          REFERENCES membership (tenant_id, identity_id),
        CONSTRAINT fk_exception_role FOREIGN KEY (tenant_id, role_key)
          REFERENCES role_definition (tenant_id, role_key),
        CONSTRAINT fk_exception_issuer FOREIGN KEY (tenant_id, issued_by)
          REFERENCES membership (tenant_id, identity_id)
      );
      CREATE INDEX ix_exception_identity ON record_exception (tenant_id, permission_key, identity_id, object_id);
      CREATE INDEX ix_exception_role ON record_exception (tenant_id, permission_key, role_key, object_id);
      CREATE INDEX ix_exception_expiry ON record_exception (tenant_id, expires_at);
      CREATE INDEX ix_exception_object ON record_exception (tenant_id, object_id, type_key);
      CREATE INDEX ix_exception_permission ON record_exception (tenant_id, permission_key, type_key);
      CREATE INDEX ix_exception_membership ON record_exception (tenant_id, identity_id);
      CREATE INDEX ix_exception_role_definition ON record_exception (tenant_id, role_key);
      CREATE INDEX ix_exception_issuer ON record_exception (tenant_id, issued_by);

      CREATE TABLE resource_relation_definition (
        tenant_id uuid NOT NULL,
        ${key('relation_key', 96)},
        relation_version integer NOT NULL CONSTRAINT ck_relation_version CHECK (relation_version > 0),
        ${key('source_type', 96)},
        ${key('target_type', 96)},
        binding_kind varchar(16) NOT NULL CONSTRAINT ck_binding_kind CHECK (binding_kind IN ('edgeStore', 'domain')),
        ${key('binding_key', 128)},
        ${hash('definition_hash')},
        ${lifecycle},
        PRIMARY KEY (tenant_id, relation_key, relation_version),
        CONSTRAINT uq_relation_types UNIQUE (tenant_id, relation_key, relation_version, source_type, target_type),
        CONSTRAINT fk_relation_source_type FOREIGN KEY (tenant_id, source_type)
          REFERENCES resource_type (tenant_id, type_key),
        CONSTRAINT fk_relation_target_type FOREIGN KEY (tenant_id, target_type)
          REFERENCES resource_type (tenant_id, type_key)
      );
      CREATE INDEX ix_relation_source_type ON resource_relation_definition (tenant_id, source_type);
      CREATE INDEX ix_relation_target_type ON resource_relation_definition (tenant_id, target_type);

      CREATE TABLE relation_edge (
        tenant_id uuid NOT NULL,
        ${key('relation_key', 96)},
        relation_version integer NOT NULL,
        source_object uuid NOT NULL,
        ${key('source_type', 96)},
        target_object uuid NOT NULL,
        ${key('target_type', 96)},
        starts_at timestamptz(6) NOT NULL,
        expires_at timestamptz(6),
        ${key('seed_owner', 128, true)},
        ${key('seed_key', 128, true)},
        PRIMARY KEY (tenant_id, relation_key, relation_version, source_object, target_object),
        CONSTRAINT uq_relation_seed UNIQUE (tenant_id, seed_owner, seed_key),
        CONSTRAINT ck_edge_interval CHECK (expires_at IS NULL OR expires_at > starts_at),
        CONSTRAINT ck_edge_seed CHECK ((seed_owner IS NULL) = (seed_key IS NULL)),
        CONSTRAINT fk_edge_definition FOREIGN KEY (tenant_id, relation_key, relation_version, source_type, target_type)
          REFERENCES resource_relation_definition (tenant_id, relation_key, relation_version, source_type, target_type),
        CONSTRAINT fk_edge_source FOREIGN KEY (tenant_id, source_object, source_type)
          REFERENCES object_ref (tenant_id, object_id, type_key) ON DELETE CASCADE,
        CONSTRAINT fk_edge_target FOREIGN KEY (tenant_id, target_object, target_type)
          REFERENCES object_ref (tenant_id, object_id, type_key) ON DELETE CASCADE
      );
      CREATE INDEX ix_edge_target ON relation_edge (tenant_id, relation_key, relation_version, target_object, source_object);
      CREATE INDEX ix_edge_source_object ON relation_edge (tenant_id, source_object, source_type);
      CREATE INDEX ix_edge_target_object ON relation_edge (tenant_id, target_object, target_type);

      CREATE TABLE identity_relation (
        tenant_id uuid NOT NULL,
        ${key('relation_key', 96)},
        object_id uuid NOT NULL,
        identity_id uuid NOT NULL,
        starts_at timestamptz(6) NOT NULL,
        expires_at timestamptz(6),
        PRIMARY KEY (tenant_id, relation_key, object_id, identity_id),
        CONSTRAINT ck_identity_relation_interval CHECK (expires_at IS NULL OR expires_at > starts_at),
        CONSTRAINT fk_identity_relation_object FOREIGN KEY (tenant_id, object_id)
          REFERENCES object_ref (tenant_id, object_id) ON DELETE CASCADE,
        CONSTRAINT fk_identity_relation_membership FOREIGN KEY (tenant_id, identity_id)
          REFERENCES membership (tenant_id, identity_id)
      );
      CREATE INDEX ix_identity_relation ON identity_relation (tenant_id, relation_key, identity_id, object_id);
      CREATE INDEX ix_identity_relation_object ON identity_relation (tenant_id, object_id);
      CREATE INDEX ix_identity_relation_membership ON identity_relation (tenant_id, identity_id);

      CREATE TABLE audit_outbox (
        ${anchor},
        event_id uuid NOT NULL,
        actor_id uuid NOT NULL,
        ${key('event_kind', 96)},
        ${key('permission_key', 160, true)},
        object_id uuid,
        policy_revision bigint NOT NULL,
        occurred_at timestamptz(6) NOT NULL,
        reason varchar(1000),
        safe_metadata jsonb NOT NULL,
        delivered_at timestamptz(6),
        PRIMARY KEY (tenant_id, event_id)
      );
      CREATE INDEX ix_audit_pending ON audit_outbox (tenant_id, delivered_at, occurred_at, event_id);
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DROP TABLE audit_outbox, identity_relation, relation_edge, resource_relation_definition,
        record_exception, object_ref, policy_rule, member_role, role_definition, scope_template,
        permission_catalog, permission_policy, resource_type, membership, authz_fence, tenant_anchor
    `);
  }
}
