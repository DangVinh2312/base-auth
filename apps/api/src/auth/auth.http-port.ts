import type {
  ProductIdentityService,
  ProductOidcService,
  ProductSessionIdentity,
} from '@base-authorization/typeorm-postgres';
import type { AppConfig } from '../config/app.config.js';

export const AUTH_HTTP_PORT = Symbol('AUTH_HTTP_PORT');

/** Bound session/identity operations: no transactions, pools, connection settings or offline commands. */
export interface AuthHttpPort {
  readonly config: Pick<AppConfig, 'origin' | 'localEnabled'>;
  readonly identity: Pick<
    ProductIdentityService,
    | 'login'
    | 'activate'
    | 'reauthenticate'
    | 'logout'
    | 'requestPasswordReset'
    | 'resetPassword'
    | 'changePassword'
  >;
  readonly oidc: Pick<ProductOidcService, 'begin' | 'callback' | 'unlink'>;
  readonly recoveryDelivery: ((userId: string, secret: string) => Promise<void>) | undefined;

  currentSession(secret: string): Promise<ProductSessionIdentity>;
}
