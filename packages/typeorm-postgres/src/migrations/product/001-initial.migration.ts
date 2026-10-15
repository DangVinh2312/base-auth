import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Bounded byte key, the PostgreSQL mapping of VARBINARY(n) in spec section 6. */
const key = (column: string, max: number, nullable = false) =>
  `${column} bytea ${nullable ? '' : 'NOT NULL '}CONSTRAINT ck_${column}_length CHECK (octet_length(${column}) BETWEEN 1 AND ${max})`;

const hash = (column: string) =>
  `${column} bytea NOT NULL CONSTRAINT ck_${column}_length CHECK (octet_length(${column}) = 32)`;

const lifecycle = `lifecycle varchar(16) NOT NULL CONSTRAINT ck_lifecycle CHECK (lifecycle IN ('active', 'deprecated', 'retired'))`;
const keyKind = `key_kind varchar(16) NOT NULL CONSTRAINT ck_key_kind CHECK (key_kind IN ('integer', 'uuid', 'string'))`;
const managedBy = `managed_by varchar(16) NOT NULL CONSTRAINT ck_managed_by CHECK (managed_by IN ('code', 'runtime'))`;

const oneSubject = `CONSTRAINT ck_one_subject CHECK ((user_id IS NOT NULL AND role_key IS NULL) OR (user_id IS NULL AND role_key IS NOT NULL))`;

/** Single-product identity and authority schema; legacy data needs an explicit mapping. */
export class ProductInitial1792108800000 implements MigrationInterface {
  name = 'ProductInitial1792108800000';

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $guard$ BEGIN
        IF to_regclass('public.tenant_anchor') IS NOT NULL OR to_regclass('public.identity_record') IS NOT NULL THEN
          RAISE EXCEPTION 'legacy identity/tenant schema requires explicit reviewed mapping; no automatic merge';
        END IF;
      END $guard$;
      CREATE TABLE authz_state (
        singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
        revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
        manifest_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex') CHECK (octet_length(manifest_hash)=32),
        release_sequence bigint NOT NULL DEFAULT 0 CHECK (release_sequence>=0),
        materialized_hash bytea CHECK(materialized_hash IS NULL OR octet_length(materialized_hash)=32),
        min_runtime_capability smallint NOT NULL DEFAULT 1 CHECK (min_runtime_capability>=0)
      );
      INSERT INTO authz_state(singleton) VALUES(true);
      CREATE TABLE app_user (
        id uuid PRIMARY KEY,
        email_canonical text UNIQUE,
        email_verified boolean NOT NULL DEFAULT false,
        state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','suspended')),
        auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0),
        authority_level smallint NOT NULL DEFAULT 0 CHECK(authority_level BETWEEN 0 AND 1000)
      );
      CREATE TABLE local_credential (
        user_id uuid PRIMARY KEY REFERENCES app_user(id), password_hash text NOT NULL,
        version bigint NOT NULL DEFAULT 1 CHECK(version>0)
      );
      CREATE TABLE external_identity (
        issuer text NOT NULL, subject text NOT NULL, user_id uuid NOT NULL REFERENCES app_user(id),
        binding_version bigint NOT NULL DEFAULT 1 CHECK(binding_version>0), enabled boolean NOT NULL DEFAULT true,
        PRIMARY KEY(issuer,subject)
      );
      CREATE INDEX ix_external_user ON external_identity(user_id);
      CREATE TABLE application_session (
        token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32), user_id uuid NOT NULL REFERENCES app_user(id),
        auth_epoch bigint NOT NULL, credential_version bigint, method text NOT NULL CHECK(method IN ('local','oidc')),
        assurance text NOT NULL, external_issuer text, external_subject text, binding_version bigint, provider_version bigint,
        last_seen_at timestamptz NOT NULL DEFAULT statement_timestamp(), reauthenticated_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT statement_timestamp(), authenticated_at timestamptz NOT NULL,
        expires_at timestamptz NOT NULL, revoked_at timestamptz,
        CHECK(expires_at>created_at), CHECK((method='local' AND credential_version IS NOT NULL) OR
          (method='oidc' AND external_issuer IS NOT NULL AND external_subject IS NOT NULL AND binding_version IS NOT NULL AND provider_version IS NOT NULL))
      );
      CREATE INDEX ix_session_user ON application_session(user_id);
      CREATE TABLE one_time_token (
        token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32), user_id uuid NOT NULL REFERENCES app_user(id),
        purpose text NOT NULL CHECK(purpose IN ('activation','reset')), expires_at timestamptz NOT NULL,
        consumed_at timestamptz, credential_version bigint
      );
      CREATE INDEX ix_token_user ON one_time_token(user_id);
      CREATE TABLE oidc_login_attempt (
        state_hash bytea PRIMARY KEY CHECK(octet_length(state_hash)=32), nonce text NOT NULL,
        browser_hash bytea NOT NULL, verifier text NOT NULL, provider_issuer text NOT NULL,
        provider_version bigint NOT NULL, redirect_uri text NOT NULL,
        purpose text NOT NULL DEFAULT 'login' CHECK(purpose IN ('login','link','reauth','activation')), linking_session_hash bytea, enrollment_hash bytea, linking_user_id uuid REFERENCES app_user(id),
        expires_at timestamptz NOT NULL, consumed_at timestamptz
      );
      CREATE TABLE oidc_provider (issuer text PRIMARY KEY, version bigint NOT NULL CHECK(version>0), enabled boolean NOT NULL);
      CREATE TABLE rate_limit (bucket_key bytea PRIMARY KEY, window_start timestamptz NOT NULL, attempts integer NOT NULL CHECK(attempts>=0));
      CREATE TABLE security_bootstrap_state (
        singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), operation_id uuid UNIQUE,
        target_user_id uuid REFERENCES app_user(id), initialized_at timestamptz,
        CHECK((operation_id IS NULL AND target_user_id IS NULL AND initialized_at IS NULL) OR
          (operation_id IS NOT NULL AND target_user_id IS NOT NULL AND initialized_at IS NOT NULL))
      );
      INSERT INTO security_bootstrap_state(singleton) VALUES(true);

      CREATE TABLE resource_type (
        
        ${key('type_key', 96)},
        ${keyKind},
        ${key('binding_key', 128)},
        PRIMARY KEY (type_key)
      );

      CREATE TABLE permission_policy (
        
        ${key('policy_key', 128)},
        policy_version integer NOT NULL CONSTRAINT ck_policy_version CHECK (policy_version > 0),
        ${hash('definition_hash')},
        definition jsonb NOT NULL,
        ${lifecycle},
        PRIMARY KEY (policy_key, policy_version)
      );

      CREATE TABLE permission_catalog (
        
        ${key('permission_key', 160)},
        ${key('type_key', 96)},
        ${key('action_key', 64)},
        ${key('policy_key', 128)},
        policy_version integer NOT NULL,
        ${lifecycle},
        boundary_requirement text NOT NULL CHECK(boundary_requirement IN ('required','optional')),
        PRIMARY KEY (permission_key),
        CONSTRAINT uq_permission_action UNIQUE (type_key, action_key),
        CONSTRAINT uq_permission_type UNIQUE (permission_key, type_key),
        CONSTRAINT fk_permission_type FOREIGN KEY (type_key)
          REFERENCES resource_type (type_key),
        CONSTRAINT fk_permission_policy FOREIGN KEY (policy_key, policy_version)
          REFERENCES permission_policy (policy_key, policy_version)
      );
      CREATE INDEX ix_permission_policy ON permission_catalog (policy_key, policy_version);

      CREATE TABLE scope_template (
        
        ${key('template_key', 128)},
        version integer NOT NULL CONSTRAINT ck_template_version CHECK (version > 0),
        ${hash('definition_hash')},
        PRIMARY KEY (template_key, version)
      );

      CREATE TABLE role_definition (
        
        ${key('role_key', 96)},
        ${managedBy},
        authority_level smallint NOT NULL CONSTRAINT ck_role_level CHECK (authority_level BETWEEN 0 AND 1000),
        label varchar(120) NOT NULL,
        PRIMARY KEY (role_key)
      );

      CREATE TABLE user_role (
        
        user_id uuid NOT NULL,
        ${key('role_key', 96)},
        PRIMARY KEY (user_id, role_key),
        CONSTRAINT fk_user_role_membership FOREIGN KEY (user_id)
          REFERENCES app_user (id),
        CONSTRAINT fk_user_role_role FOREIGN KEY (role_key)
          REFERENCES role_definition (role_key)
      );
      CREATE INDEX ix_role_members ON user_role (role_key, user_id);

      CREATE TABLE policy_rule (
        
        rule_id uuid NOT NULL,
        ${key('permission_key', 160)},
        user_id uuid,
        ${key('role_key', 96, true)},
        effect varchar(8) NOT NULL CONSTRAINT ck_effect CHECK (effect IN ('allow', 'deny')),
        ${key('template_key', 128)},
        template_version integer NOT NULL,
        parameters jsonb NOT NULL,
        ${managedBy},
        system_owner bytea, system_key bytea,
        UNIQUE(system_owner, system_key),
        CHECK((system_owner IS NULL)=(system_key IS NULL)),
        CHECK(system_owner IS NULL OR managed_by='code'),

        PRIMARY KEY (rule_id),
        ${oneSubject},
        CONSTRAINT fk_rule_permission FOREIGN KEY (permission_key)
          REFERENCES permission_catalog (permission_key),
        CONSTRAINT fk_rule_membership FOREIGN KEY (user_id)
          REFERENCES app_user (id),
        CONSTRAINT fk_rule_role FOREIGN KEY (role_key)
          REFERENCES role_definition (role_key),
        CONSTRAINT fk_rule_template FOREIGN KEY (template_key, template_version)
          REFERENCES scope_template (template_key, version)
      );
      CREATE INDEX ix_rule_identity ON policy_rule (permission_key, user_id, effect);
      CREATE INDEX ix_rule_role ON policy_rule (permission_key, role_key, effect);
      CREATE INDEX ix_rule_membership ON policy_rule (user_id);
      CREATE INDEX ix_rule_role_definition ON policy_rule (role_key);
      CREATE INDEX ix_rule_template ON policy_rule (template_key, template_version);

      CREATE TABLE object_ref (
        
        object_id uuid NOT NULL,
        ${key('type_key', 96)},
        ${keyKind},
        ${key('key_bytes', 256)},
        PRIMARY KEY (object_id),
        CONSTRAINT uq_object_key UNIQUE (type_key, key_kind, key_bytes),
        CONSTRAINT uq_object_type UNIQUE (object_id, type_key),
        CONSTRAINT fk_object_type FOREIGN KEY (type_key)
          REFERENCES resource_type (type_key)
      );

      CREATE TABLE record_exception (
        
        exception_id uuid NOT NULL,
        object_id uuid NOT NULL,
        ${key('type_key', 96)},
        ${key('permission_key', 160)},
        user_id uuid,
        ${key('role_key', 96, true)},
        effect varchar(8) NOT NULL CONSTRAINT ck_effect CHECK (effect IN ('allow', 'deny')),
        purpose varchar(16) NOT NULL CONSTRAINT ck_exception_purpose CHECK (purpose IN ('manual', 'emergency')),
        starts_at timestamptz(6) NOT NULL,
        expires_at timestamptz(6),
        reason varchar(1000) NOT NULL CONSTRAINT ck_exception_reason CHECK (char_length(btrim(reason)) > 0),
        issued_by uuid NOT NULL,
        revoked_at timestamptz(6),
        PRIMARY KEY (exception_id),
        ${oneSubject},
        CONSTRAINT ck_exception_interval CHECK (expires_at IS NULL OR expires_at > starts_at),
        CONSTRAINT ck_exception_emergency CHECK (
          purpose <> 'emergency' OR (expires_at IS NOT NULL AND effect = 'allow' AND user_id IS NOT NULL)
        ),
        CONSTRAINT fk_exception_object FOREIGN KEY (object_id, type_key)
          REFERENCES object_ref (object_id, type_key) ON DELETE CASCADE,
        CONSTRAINT fk_exception_permission FOREIGN KEY (permission_key, type_key)
          REFERENCES permission_catalog (permission_key, type_key),
        CONSTRAINT fk_exception_membership FOREIGN KEY (user_id)
          REFERENCES app_user (id),
        CONSTRAINT fk_exception_role FOREIGN KEY (role_key)
          REFERENCES role_definition (role_key),
        CONSTRAINT fk_exception_issuer FOREIGN KEY (issued_by)
          REFERENCES app_user (id)
      );
      CREATE INDEX ix_exception_identity ON record_exception (permission_key, user_id, object_id);
      CREATE INDEX ix_exception_role ON record_exception (permission_key, role_key, object_id);
      CREATE INDEX ix_exception_expiry ON record_exception (expires_at);
      CREATE INDEX ix_exception_object ON record_exception (object_id, type_key);
      CREATE INDEX ix_exception_permission ON record_exception (permission_key, type_key);
      CREATE INDEX ix_exception_membership ON record_exception (user_id);
      CREATE INDEX ix_exception_role_definition ON record_exception (role_key);
      CREATE INDEX ix_exception_issuer ON record_exception (issued_by);

      CREATE TABLE resource_relation_definition (
        
        ${key('relation_key', 96)},
        relation_version integer NOT NULL CONSTRAINT ck_relation_version CHECK (relation_version > 0),
        ${key('source_type', 96)},
        ${key('target_type', 96)},
        binding_kind varchar(16) NOT NULL CONSTRAINT ck_binding_kind CHECK (binding_kind IN ('edgeStore', 'domain')),
        ${key('binding_key', 128)},
        ${hash('definition_hash')},
        ${lifecycle},
        PRIMARY KEY (relation_key, relation_version),
        CONSTRAINT uq_relation_types UNIQUE (relation_key, relation_version, source_type, target_type),
        CONSTRAINT fk_relation_source_type FOREIGN KEY (source_type)
          REFERENCES resource_type (type_key),
        CONSTRAINT fk_relation_target_type FOREIGN KEY (target_type)
          REFERENCES resource_type (type_key)
      );
      CREATE INDEX ix_relation_source_type ON resource_relation_definition (source_type);
      CREATE INDEX ix_relation_target_type ON resource_relation_definition (target_type);

      CREATE TABLE relation_edge (
        
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
        PRIMARY KEY (relation_key, relation_version, source_object, target_object),
        CONSTRAINT uq_relation_seed UNIQUE (seed_owner, seed_key),
        CONSTRAINT ck_edge_interval CHECK (expires_at IS NULL OR expires_at > starts_at),
        CONSTRAINT ck_edge_seed CHECK ((seed_owner IS NULL) = (seed_key IS NULL)),
        CONSTRAINT fk_edge_definition FOREIGN KEY (relation_key, relation_version, source_type, target_type)
          REFERENCES resource_relation_definition (relation_key, relation_version, source_type, target_type),
        CONSTRAINT fk_edge_source FOREIGN KEY (source_object, source_type)
          REFERENCES object_ref (object_id, type_key) ON DELETE CASCADE,
        CONSTRAINT fk_edge_target FOREIGN KEY (target_object, target_type)
          REFERENCES object_ref (object_id, type_key) ON DELETE CASCADE
      );
      CREATE INDEX ix_edge_target ON relation_edge (relation_key, relation_version, target_object, source_object);
      CREATE INDEX ix_edge_source_object ON relation_edge (source_object, source_type);
      CREATE INDEX ix_edge_target_object ON relation_edge (target_object, target_type);

      CREATE TABLE user_relation (
        
        ${key('relation_key', 96)},
        object_id uuid NOT NULL,
        user_id uuid NOT NULL,
        starts_at timestamptz(6) NOT NULL,
        expires_at timestamptz(6),
        PRIMARY KEY (relation_key, object_id, user_id),
        CONSTRAINT ck_user_relation_interval CHECK (expires_at IS NULL OR expires_at > starts_at),
        CONSTRAINT fk_user_relation_object FOREIGN KEY (object_id)
          REFERENCES object_ref (object_id) ON DELETE CASCADE,
        CONSTRAINT fk_user_relation_membership FOREIGN KEY (user_id)
          REFERENCES app_user (id)
      );
      CREATE INDEX ix_user_relation ON user_relation (relation_key, user_id, object_id);
      CREATE INDEX ix_user_relation_object ON user_relation (object_id);
      CREATE INDEX ix_user_relation_membership ON user_relation (user_id);

      CREATE TABLE permission_boundary (
        
        ${key('boundary_key', 128)},
        boundary_version integer NOT NULL CONSTRAINT ck_boundary_version CHECK (boundary_version > 0),
        definition_hash bytea NOT NULL CONSTRAINT ck_definition_hash_length CHECK (octet_length(definition_hash) = 32),
        definition jsonb NOT NULL,
        lifecycle varchar(16) NOT NULL CONSTRAINT ck_lifecycle CHECK (lifecycle IN ('active', 'deprecated', 'retired')),
        PRIMARY KEY (boundary_key, boundary_version)
      );

      CREATE TABLE permission_boundary_entry (
        
        ${key('boundary_key', 128)},
        boundary_version integer NOT NULL,
        ${key('permission_key', 160)},
        definition jsonb NOT NULL,
        PRIMARY KEY (boundary_key, boundary_version, permission_key),
        CONSTRAINT fk_boundary_entry_boundary FOREIGN KEY (boundary_key, boundary_version)
          REFERENCES permission_boundary (boundary_key, boundary_version),
        CONSTRAINT fk_boundary_entry_permission FOREIGN KEY (permission_key)
          REFERENCES permission_catalog (permission_key)
      );
      CREATE INDEX ix_boundary_entry_permission ON permission_boundary_entry (permission_key);

      CREATE TABLE user_boundary (
        
        user_id uuid NOT NULL,
        ${key('permission_key', 160)},
        ${key('boundary_key', 128)},
        boundary_version integer NOT NULL,
        ${key('seed_owner', 128, true)},
        PRIMARY KEY (user_id, permission_key),
        CONSTRAINT fk_member_boundary_membership FOREIGN KEY (user_id)
          REFERENCES app_user (id),
        CONSTRAINT fk_member_boundary_entry FOREIGN KEY (boundary_key, boundary_version, permission_key)
          REFERENCES permission_boundary_entry (boundary_key, boundary_version, permission_key)
      );
      CREATE INDEX ix_member_boundary_entry
        ON user_boundary (boundary_key, boundary_version, permission_key);

      CREATE TABLE audit_outbox (
        
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
        PRIMARY KEY (event_id)
      );
      CREATE INDEX ix_audit_pending ON audit_outbox (delivered_at, occurred_at, event_id);
    `);
  }

  down(): Promise<void> {
    return Promise.reject(
      new Error(
        'Product identity migration requires an explicit restore; automatic destructive downgrade is disabled',
      ),
    );
  }
}
