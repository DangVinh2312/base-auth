import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * 1. `identity_relation.relation_version` becomes a column. Legacy rows stored `key@version` in
 *    `relation_key`; anything not in that exact form stops the migration (no guessing).
 * 2. Shared tenant fence function. Data credentials get EXECUTE on it and no privilege on
 *    `authz_fence`; provisioning hands ownership to a dedicated NOLOGIN role (ADR 0001/0002).
 */
export class TenantRelationVersion1791936000000 implements MigrationInterface {
  name = 'TenantRelationVersion1791936000000';

  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$
      DECLARE unconvertible bigint;
      BEGIN
        SELECT count(*) INTO unconvertible FROM identity_relation
        WHERE convert_from(relation_key, 'UTF8')
          !~ '^[a-z][A-Za-z0-9_]*(\\.[a-z][A-Za-z0-9_]*)*@[1-9][0-9]{0,8}$';
        IF unconvertible > 0 THEN
          RAISE EXCEPTION 'identity_relation has % row(s) whose relation_key is not key@version; fix them before migrating', unconvertible;
        END IF;
      END $$;

      ALTER TABLE identity_relation ADD COLUMN relation_version integer;
      UPDATE identity_relation SET
        relation_version = substring(convert_from(relation_key, 'UTF8') from '@([0-9]+)$')::integer,
        relation_key = convert_to(substring(convert_from(relation_key, 'UTF8') from '^(.*)@[0-9]+$'), 'UTF8');
      ALTER TABLE identity_relation
        ALTER COLUMN relation_version SET NOT NULL,
        ADD CONSTRAINT ck_identity_relation_version CHECK (relation_version > 0),
        DROP CONSTRAINT identity_relation_pkey,
        ADD CONSTRAINT identity_relation_pkey
          PRIMARY KEY (tenant_id, relation_key, relation_version, object_id, identity_id);
      DROP INDEX ix_identity_relation;
      CREATE INDEX ix_identity_relation
        ON identity_relation (tenant_id, relation_key, relation_version, identity_id, object_id);

      CREATE FUNCTION public.authz_acquire_shared_fence(p_tenant uuid) RETURNS bigint
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
      REVOKE ALL ON FUNCTION public.authz_acquire_shared_fence(uuid) FROM PUBLIC;
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DROP FUNCTION public.authz_acquire_shared_fence(uuid);
      DROP INDEX ix_identity_relation;
      ALTER TABLE identity_relation DROP CONSTRAINT identity_relation_pkey;
      UPDATE identity_relation
        SET relation_key = relation_key || convert_to('@' || relation_version::text, 'UTF8');
      ALTER TABLE identity_relation
        DROP COLUMN relation_version,
        ADD CONSTRAINT identity_relation_pkey PRIMARY KEY (tenant_id, relation_key, object_id, identity_id);
      CREATE INDEX ix_identity_relation ON identity_relation (tenant_id, relation_key, identity_id, object_id);
    `);
  }
}
