import { Injectable } from '@nestjs/common';

/** Fail-closed readiness: not ready until the bootstrap coordinator marks it so. */
@Injectable()
export class ReadinessGate {
  #ready = false;
  readonly #tenants = new Set<string>();

  get ready(): boolean {
    return this.#ready;
  }

  markReady(): void {
    this.#ready = true;
  }

  isTenantReady(tenant: string): boolean {
    return this.#tenants.has(tenant);
  }

  markTenantReady(tenant: string): void {
    this.#tenants.add(tenant);
  }
}
