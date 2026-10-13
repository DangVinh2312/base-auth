import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Existing unversioned tuples need explicit declaration mapping before upgrading. */
export class ProductUserRelationVersion1792108800003 implements MigrationInterface {
  name = 'ProductUserRelationVersion1792108800003';
  async up(runner: QueryRunner): Promise<void> {
    await runner.query(`
      DO $guard$ BEGIN
        IF EXISTS(SELECT FROM public.user_relation) THEN
          RAISE EXCEPTION 'unversioned user relations require explicit reviewed mapping';
        END IF;
      END $guard$;
      ALTER TABLE public.user_relation ADD COLUMN relation_version integer NOT NULL CHECK(relation_version>0);
      ALTER TABLE public.user_relation DROP CONSTRAINT user_relation_pkey;
      ALTER TABLE public.user_relation ADD PRIMARY KEY(relation_key,relation_version,object_id,user_id);
      CREATE INDEX ix_user_relation_version ON public.user_relation(relation_key,relation_version,user_id,object_id);
    `);
  }
  down(): Promise<void> {
    return Promise.reject(new Error('Relation versions require explicit restore'));
  }
}
