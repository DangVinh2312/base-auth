import type { ProductPage, ProductRow } from '@base-authorization/typeorm-postgres';
import type { AppConfig } from '../config/app.config.js';
export const DOCUMENTS_HTTP_PORT = Symbol('DOCUMENTS_HTTP_PORT');
/** Resource and action are bound at composition; a handler cannot choose another permission. */
export interface DocumentsHttpPort {
  readonly config: Pick<AppConfig, 'origin'>;
  /** document.read */
  list(sessionSecret: string): Promise<ProductPage>;
  /** document.read; null for absent and hidden alike */
  detail(sessionSecret: string, id: string): Promise<ProductRow | null>;
  /** document.update; false for absent, hidden or out of scope */
  update(sessionSecret: string, id: string, changes: { readonly title: string }): Promise<boolean>;
}
