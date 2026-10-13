import type {
  ProductAuthorization,
  ProductIdentityService,
  ProductOidcService,
  ProductSessionIdentity,
} from '@base-authorization/typeorm-postgres';
import type { AppConfig } from './config.js';
import type { ProductMetrics } from './metrics.js';
export const PRODUCT_HTTP_SERVICES = Symbol('PRODUCT_HTTP_SERVICES');
/** Handler-facing operations contain no pools, connection settings, manifest writer or bootstrap capability. */
export interface ProductHttpServices {
  readonly config: Pick<AppConfig, 'origin' | 'localEnabled'>;
  readonly authorization: Pick<
    ProductAuthorization,
    'list' | 'detail' | 'update' | 'suspendUser' | 'checkSession'
  >;
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
  readonly metrics: Pick<ProductMetrics, 'snapshot'>;
  readonly recoveryDelivery: ((userId: string, secret: string) => Promise<void>) | undefined;
  currentSession(secret: string): Promise<ProductSessionIdentity>;
}
