import type {
  Page as ProductPage,
  Row as ProductRow,
} from '../authorization/product-data.gateway.js';
import type { AppConfig } from '../config/app.config.js';

export const DOCUMENT_HTTP_PORT = Symbol('DOCUMENT_HTTP_PORT');

/** Resource and action are bound at composition; a handler cannot choose another permission. */
export interface DocumentHttpPort {
  readonly config: Pick<AppConfig, 'origin'>;

  /** document.read */
  list(sessionSecret: string): Promise<ProductPage>;

  /** document.read; null for absent and hidden alike */
  detail(sessionSecret: string, id: string): Promise<ProductRow | null>;

  /** document.update; false for absent, hidden or out of scope */
  update(sessionSecret: string, id: string, changes: { readonly title: string }): Promise<boolean>;
}
