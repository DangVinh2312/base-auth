import { Module } from '@nestjs/common';
import { HealthController } from './health.controller.js';
/** Needs ReadinessGate and METRICS_SNAPSHOT; AppModule supplies the runtime module that exports them. */
@Module({ controllers: [HealthController] })
export class HealthModule {}
