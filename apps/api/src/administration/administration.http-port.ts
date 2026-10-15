import type { AppConfig } from '../config/app.config.js';

export const ADMINISTRATION_HTTP_PORT = Symbol('ADMINISTRATION_HTTP_PORT');

/** Trusted administration commands; each rechecks session, policy and boundary in its transaction. */
export interface AdministrationHttpPort {
  readonly config: Pick<AppConfig, 'origin'>;

  /** account.suspend; false for absent or not visible */
  suspendUser(sessionSecret: string, userId: string): Promise<boolean>;
}
