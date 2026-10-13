import { PRODUCT_HTTP_SERVICES } from './http-services.js';
import { Module, type DynamicModule } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ReadinessGate, ProductAuthorizationModule } from '@base-authorization/nest';
import { HealthController } from './health.controller.js';
import { ProductController } from './product.controller.js';
import { ProductRuntime } from './product-runtime.js';
import { productRelease } from './product-manifest.js';
import { sessionSecret, type HttpRequest } from './http-security.js';
import { ProductErrorFilter } from './product.filter.js';
@Module({})
export class AppModule {
  static register(runtime: ProductRuntime): DynamicModule {
    return {
      module: AppModule,
      imports: [
        ProductAuthorizationModule.register({
          declarations: productRelease.declarations,
          requestAuth: {
            authenticate: (request) =>
              runtime.authorization.checkSession(
                sessionSecret(request as HttpRequest, runtime.config),
              ),
          },
        }),
      ],
      controllers: [HealthController, ProductController],
      providers: [
        { provide: ProductRuntime, useValue: runtime },
        { provide: PRODUCT_HTTP_SERVICES, useValue: runtime.httpServices() },
        { provide: ReadinessGate, useValue: runtime.readiness },
        { provide: APP_FILTER, useClass: ProductErrorFilter },
      ],
    };
  }
}
