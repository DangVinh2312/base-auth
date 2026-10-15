import { Module, type DynamicModule } from '@nestjs/common';
import { ReadinessGate } from '@base-authorization/nest';
import {
  ADMINISTRATION_HTTP_PORT,
  type AdministrationHttpPort,
} from '../administration/administration.http-port.js';
import { AUTH_HTTP_PORT, type AuthHttpPort } from '../auth/auth.http-port.js';
import { DOCUMENT_HTTP_PORT, type DocumentHttpPort } from '../document/document.http-port.js';
import { METRICS_SNAPSHOT, type MetricsSnapshot } from '../health/product-metrics.service.js';
import { ProductRuntime } from './product-runtime.service.js';

/**
 * Owns the runtime (pools, release, transaction runner) as a private provider so Nest runs its
 * bootstrap/shutdown hooks; feature modules import this module and see only the exported facades
 * of bound operations. Never global, never exports ProductRuntime.
 */
@Module({})
export class RuntimeModule {
  static register(runtime: ProductRuntime): DynamicModule {
    const { authorization, identity, oidc, metrics } = runtime;
    const config = { origin: runtime.config.origin, localEnabled: runtime.config.localEnabled };
    // Factories rather than values: Nest hashes module metadata, which must not walk the pools.
    return {
      module: RuntimeModule,
      providers: [
        {
          provide: ProductRuntime,

          useFactory: () => runtime,
        },
        {
          provide: ReadinessGate,

          useFactory: () => runtime.readiness,
        },
        {
          provide: METRICS_SNAPSHOT,

          useFactory: (): MetricsSnapshot => ({ snapshot: metrics.snapshot.bind(metrics) }),
        },
        {
          provide: AUTH_HTTP_PORT,

          useFactory: (): AuthHttpPort => ({
            config,
            identity: {
              login: identity.login.bind(identity),
              activate: identity.activate.bind(identity),
              reauthenticate: identity.reauthenticate.bind(identity),
              logout: identity.logout.bind(identity),
              requestPasswordReset: identity.requestPasswordReset.bind(identity),
              resetPassword: identity.resetPassword.bind(identity),
              changePassword: identity.changePassword.bind(identity),
            },
            oidc: {
              begin: oidc.begin.bind(oidc),
              callback: oidc.callback.bind(oidc),
              unlink: oidc.unlink.bind(oidc),
            },
            recoveryDelivery: runtime.recoveryDelivery,
            currentSession: runtime.currentSession.bind(runtime),
          }),
        },
        {
          provide: DOCUMENT_HTTP_PORT,

          useFactory: (): DocumentHttpPort => ({
            config,

            list: (secret) => authorization.list(secret, 'document', 'read'),

            detail: (secret, id) => authorization.detail(secret, 'document', 'read', id),

            update: (secret, id, changes) =>
              authorization.update(secret, 'document', 'update', id, changes),
          }),
        },
        {
          provide: ADMINISTRATION_HTTP_PORT,

          useFactory: (): AdministrationHttpPort => ({
            config,
            suspendUser: authorization.suspendUser.bind(authorization),
          }),
        },
      ],
      exports: [
        ReadinessGate,
        METRICS_SNAPSHOT,
        AUTH_HTTP_PORT,
        DOCUMENT_HTTP_PORT,
        ADMINISTRATION_HTTP_PORT,
      ],
    };
  }
}
