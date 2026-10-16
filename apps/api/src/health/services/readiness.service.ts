import { Injectable } from '@nestjs/common';

/** Fail-closed readiness: not ready until the runtime completes bootstrap. */
@Injectable()
export class ReadinessGate {
  #ready = false;

  get ready(): boolean {
    return this.#ready;
  }

  markReady(): void {
    this.#ready = true;
  }
}
