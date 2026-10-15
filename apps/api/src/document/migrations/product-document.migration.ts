import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Minimal resource fixture owned by the application; adapter migrations contain no domain. */
export class ProductDocument1792108800002 implements MigrationInterface {
  name = 'ProductDocument1792108800002';

  async up(r: QueryRunner): Promise<void> {
    await r.query(
      `CREATE TABLE document(id uuid PRIMARY KEY,object_id uuid NOT NULL UNIQUE REFERENCES object_ref(object_id),owner_id uuid NOT NULL REFERENCES app_user(id),title text NOT NULL CHECK(octet_length(title) BETWEEN 1 AND 500),state text NOT NULL CHECK(state IN('draft','published'))); CREATE INDEX ix_document_owner ON document(owner_id,id); GRANT SELECT,UPDATE(title) ON document TO product_data; GRANT SELECT ON document TO product_authority;`,
    );
  }

  down(): Promise<void> {
    return Promise.reject(new Error('Use reviewed forward migration'));
  }
}
