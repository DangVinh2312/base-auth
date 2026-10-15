import {
  type DynamicModule,
  Inject,
  Injectable,
  Logger,
  Module,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { ReadinessGate } from './readiness.service.js';

/** Injection token of the manifest sync port. Not exported from `BootstrapModule`. */
export const MANIFEST_SYNC = Symbol('MANIFEST_SYNC');

/**
 * Deploy/boot sync for this instance's tenant allowlist. The implementation holds the sync
 * credential (e.g. `ManifestReconciler` + a verified release); controllers never receive it.
 */
export interface ManifestSyncPort {
  tenants(): readonly string[] | Promise<readonly string[]>;

  reconcile(tenant: string): Promise<unknown>;
}

/**
 * Single coordinator: Nest awaits `onApplicationBootstrap` before `listen()` completes, so no
 * request is served and no worker should start before every tenant is reconciled. A tenant whose
 * sync fails stays not ready (503); the process is ready only when all tenants are.
 */
@Injectable()
export class BootstrapCoordinator implements OnApplicationBootstrap {
  readonly #logger = new Logger(BootstrapCoordinator.name);

  constructor(
    @Inject(MANIFEST_SYNC) private readonly sync: ManifestSyncPort,
    private readonly readiness: ReadinessGate,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    let allReady = true;
    for (const tenant of await this.sync.tenants()) {
      try {
        await this.sync.reconcile(tenant);
        this.readiness.markTenantReady(tenant);
      } catch (error) {
        allReady = false;
        // Error class and tenant only: no SQL, parameters or credentials in logs.
        this.#logger.error(
          `Manifest sync failed for tenant ${tenant}: ${error instanceof Error ? error.name : 'unknown'}`,
        );
      }
    }
    if (allReady) this.readiness.markReady();
  }
}

@Module({})
export class BootstrapModule {
  static forRoot(options: { sync: ManifestSyncPort }): DynamicModule {
    return {
      module: BootstrapModule,
      providers: [
        { provide: MANIFEST_SYNC, useValue: options.sync },
        ReadinessGate,
        BootstrapCoordinator,
      ],
      exports: [ReadinessGate],
    };
  }
}
