import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';
import { ProductPublic, ReadinessGate } from '@base-authorization/nest';
import { METRICS_SNAPSHOT, type MetricsSnapshot } from './product-metrics.service.js';

@Controller('health')
export class HealthController {
  constructor(
    private readonly readiness: ReadinessGate,
    @Inject(METRICS_SNAPSHOT) private readonly metrics: MetricsSnapshot,
  ) {}

  /** 200 `{status:'ok'}` while the process serves HTTP. */
  @Get('live')
  @ProductPublic()
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }

  /** 200 `{status:'ready'}` or 503 `{status:'not_ready'}`. */
  @Get('ready')
  @ProductPublic()
  ready(): { status: 'ready' } {
    if (!this.readiness.ready) throw new ServiceUnavailableException({ status: 'not_ready' });
    return { status: 'ready' };
  }

  @Get('metrics')
  @ProductPublic()
  snapshot() {
    return this.metrics.snapshot();
  }
}
