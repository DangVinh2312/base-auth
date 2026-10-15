import type { MigrationInterface, QueryRunner } from 'typeorm';

const key = (column: string, max: number, nullable = false) =>
  `${column} bytea ${nullable ? '' : 'NOT NULL '}CONSTRAINT ck_${column}_length CHECK (octet_length(${column}) BETWEEN 1 AND ${max})`;

/** Shared fence body; `p_capability` is the runtime capability of the calling binary. */
const fenceBody = (capability: string) => `
      DECLARE v_revision bigint; v_required smallint;
      BEGIN
        SELECT f.revision, f.min_runtime_capability INTO v_revision, v_required
        FROM public.authz_fence f
        WHERE f.tenant_id = p_tenant
          AND f.tenant_id = (SELECT a.tenant_id FROM public.tenant_anchor a)
        FOR SHARE OF f;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'tenant fence is missing' USING ERRCODE = 'P0002';
        END IF;
        IF v_required > ${capability} THEN
          RAISE EXCEPTION 'runtime capability % is below the tenant requirement %', ${capability}, v_required
            USING ERRCODE = 'AZ001';
        END IF;
        RETURN v_revision;
      END`;

/**
 * Permission boundary storage (ADR 0003, docs/permission-boundaries.md):
 * 1. Code-owned definitions + entries (synced by release), membership bindings (runtime or seeded).
 *    Composite FKs keep tenant, membership and permission aligned: a binding can only reference an
 *    entry of the same permission.
 * 2. `permission_catalog.boundary_requirement`: existing rows are left NULL (the migration does not
 *    know the manifest). The runtime denies a NULL requirement and the next release backfills it;
 *    the NOT VALID check rejects NULL for every row written after this migration.
 * 3. Runtime compatibility gate: `authz_fence.min_runtime_capability` (raised by sync). The old
 *    one-argument fence function now fails (AZ001) once a tenant requires capability ≥ 1, so a
 *    binary built before boundaries cannot keep serving a manifest whose boundaries it ignores.
 */
export class TenantPermissionBoundary1792022400000 implements MigrationInterface {
  name = 'TenantPermissionBoundary1792022400000';

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE permission_boundary (
        tenant_id uuid NOT NULL CONSTRAINT fk_tenant_anchor REFERENCES tenant_anchor (tenant_id),
        ${key('boundary_key', 128)},
        boundary_version integer NOT NULL CONSTRAINT ck_boundary_version CHECK (boundary_version > 0),
        definition_hash bytea NOT NULL CONSTRAINT ck_definition_hash_length CHECK (octet_length(definition_hash) = 32),
        definition jsonb NOT NULL,
        lifecycle varchar(16) NOT NULL CONSTRAINT ck_lifecycle CHECK (lifecycle IN ('active', 'deprecated', 'retired')),
        PRIMARY KEY (tenant_id, boundary_key, boundary_version)
      );

      CREATE TABLE permission_boundary_entry (
        tenant_id uuid NOT NULL,
        ${key('boundary_key', 128)},
        boundary_version integer NOT NULL,
        ${key('permission_key', 160)},
        definition jsonb NOT NULL,
        PRIMARY KEY (tenant_id, boundary_key, boundary_version, permission_key),
        CONSTRAINT fk_boundary_entry_boundary FOREIGN KEY (tenant_id, boundary_key, boundary_version)
          REFERENCES permission_boundary (tenant_id, boundary_key, boundary_version),
        CONSTRAINT fk_boundary_entry_permission FOREIGN KEY (tenant_id, permission_key)
          REFERENCES permission_catalog (tenant_id, permission_key)
      );
      CREATE INDEX ix_boundary_entry_permission ON permission_boundary_entry (tenant_id, permission_key);

      CREATE TABLE member_permission_boundary (
        tenant_id uuid NOT NULL,
        identity_id uuid NOT NULL,
        ${key('permission_key', 160)},
        ${key('boundary_key', 128)},
        boundary_version integer NOT NULL,
        ${key('seed_owner', 128, true)},
        PRIMARY KEY (tenant_id, identity_id, permission_key),
        CONSTRAINT fk_member_boundary_membership FOREIGN KEY (tenant_id, identity_id)
          REFERENCES membership (tenant_id, identity_id),
        CONSTRAINT fk_member_boundary_entry FOREIGN KEY (tenant_id, boundary_key, boundary_version, permission_key)
          REFERENCES permission_boundary_entry (tenant_id, boundary_key, boundary_version, permission_key)
      );
      CREATE INDEX ix_member_boundary_entry
        ON member_permission_boundary (tenant_id, boundary_key, boundary_version, permission_key);

      ALTER TABLE permission_catalog
        ADD COLUMN boundary_requirement varchar(16)
          CONSTRAINT ck_boundary_requirement CHECK (boundary_requirement IN ('required', 'optional')),
        ADD CONSTRAINT ck_boundary_requirement_set CHECK (boundary_requirement IS NOT NULL) NOT VALID;

      ALTER TABLE authz_fence
        ADD COLUMN min_runtime_capability smallint NOT NULL DEFAULT 0
          CONSTRAINT ck_fence_runtime_capability CHECK (min_runtime_capability >= 0);

      CREATE FUNCTION public.authz_acquire_shared_fence(p_tenant uuid, p_capability integer) RETURNS bigint
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
      AS $fence$${fenceBody('p_capability')}
      $fence$;
      REVOKE ALL ON FUNCTION public.authz_acquire_shared_fence(uuid, integer) FROM PUBLIC;

      CREATE OR REPLACE FUNCTION public.authz_acquire_shared_fence(p_tenant uuid) RETURNS bigint
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
      AS $fence$${fenceBody('0')}
      $fence$;
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION public.authz_acquire_shared_fence(p_tenant uuid) RETURNS bigint
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
      AS $fence$
      DECLARE v_revision bigint;
      BEGIN
        SELECT f.revision INTO v_revision
        FROM public.authz_fence f
        WHERE f.tenant_id = p_tenant
          AND f.tenant_id = (SELECT a.tenant_id FROM public.tenant_anchor a)
        FOR SHARE OF f;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'tenant fence is missing' USING ERRCODE = 'P0002';
        END IF;
        RETURN v_revision;
      END
      $fence$;
      DROP FUNCTION public.authz_acquire_shared_fence(uuid, integer);
      ALTER TABLE authz_fence DROP COLUMN min_runtime_capability;
      ALTER TABLE permission_catalog DROP COLUMN boundary_requirement;
      DROP TABLE member_permission_boundary, permission_boundary_entry, permission_boundary;
    `);
  }
}
