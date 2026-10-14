import {
  type CanActivate,
  type DynamicModule,
  type ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Module,
  type OnModuleInit,
} from '@nestjs/common';
import { METHOD_METADATA } from '@nestjs/common/constants.js';
import {
  APP_GUARD,
  DiscoveryModule,
  DiscoveryService,
  MetadataScanner,
  Reflector,
} from '@nestjs/core';

export const PRODUCT_REQUEST_AUTH = Symbol('PRODUCT_REQUEST_AUTH');
const ROUTE_CLASSIFICATION = Symbol('PRODUCT_ROUTE_CLASSIFICATION');
const DECLARATIONS = Symbol('PRODUCT_ROUTE_DECLARATIONS');

export interface ProductRequestAuth {
  /** Early session check only. Data services must recheck session and facts under the application fence. */
  authenticate(request: unknown): Promise<void>;
}

interface ProductRouteDeclarations {
  readonly resources: Readonly<
    Record<string, { readonly actions: Readonly<Record<string, unknown>> }>
  >;
}

type Classification =
  | { readonly kind: 'public' | 'authenticated' }
  | { readonly kind: 'authorize'; readonly resource: string; readonly action: string };

function classify(value: Classification): MethodDecorator {
  return (_target, _key, descriptor) => {
    const handler = descriptor.value;
    if (typeof handler !== 'function') throw new Error('Product classification requires a method');
    const previous = Reflect.getOwnMetadata(ROUTE_CLASSIFICATION, handler) as
      Classification[] | undefined;
    Reflect.defineMetadata(ROUTE_CLASSIFICATION, [...(previous ?? []), value], handler);
  };
}

export const ProductPublic = (): MethodDecorator => classify({ kind: 'public' });
export const ProductAuthenticated = (): MethodDecorator => classify({ kind: 'authenticated' });
export const ProductAuthorize = (resource: string, action: string): MethodDecorator =>
  classify({ kind: 'authorize', resource, action });

function classification(
  reflector: Reflector,
  handler: ReturnType<ExecutionContext['getHandler']>,
): Classification {
  const entries = reflector.get<Classification[] | undefined>(ROUTE_CLASSIFICATION, handler);
  if (entries?.length !== 1) throw new Error('Product route must have exactly one classification');
  return entries[0]!;
}

/**
 * Runs in onModuleInit: every module's onModuleInit finishes before any onApplicationBootstrap,
 * which Nest runs deepest module first. A route failure must stop boot before bootstrap hooks with
 * effects (manifest sync, readiness) start, wherever their module sits.
 */
@Injectable()
class ProductRouteInventory implements OnModuleInit {
  constructor(
    private readonly discovery: DiscoveryService,
    private readonly scanner: MetadataScanner,
    private readonly reflector: Reflector,
    @Inject(DECLARATIONS) private readonly declarations: ProductRouteDeclarations,
  ) {}

  onModuleInit(): void {
    for (const controller of this.discovery.getControllers()) {
      if (!controller.instance) throw new Error('Product controller cannot be inspected');
      const prototype = Object.getPrototypeOf(controller.instance) as Record<string, unknown>;
      for (const name of this.scanner.getAllMethodNames(prototype)) {
        const handler = prototype[name];
        if (
          typeof handler !== 'function' ||
          this.reflector.get(METHOD_METADATA, handler) === undefined
        )
          continue;
        const entry = classification(this.reflector, handler);
        if (entry.kind !== 'authorize') continue;
        const resource = Object.hasOwn(this.declarations.resources, entry.resource)
          ? this.declarations.resources[entry.resource]
          : undefined;
        if (!resource || !Object.hasOwn(resource.actions, entry.action))
          throw new Error('Product route references an undeclared permission');
      }
    }
  }
}

@Injectable()
export class ProductRouteGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(PRODUCT_REQUEST_AUTH) private readonly auth: ProductRequestAuth,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') throw new ForbiddenException();
    let entry: Classification;
    try {
      entry = classification(this.reflector, context.getHandler());
    } catch {
      throw new ForbiddenException();
    }
    if (entry.kind === 'public') return true;
    await this.auth.authenticate(context.switchToHttp().getRequest<unknown>());
    return true;
  }
}

@Module({})
export class ProductAuthorizationModule {
  static register(options: {
    declarations: ProductRouteDeclarations;
    requestAuth: ProductRequestAuth;
  }): DynamicModule {
    return {
      module: ProductAuthorizationModule,
      imports: [DiscoveryModule],
      providers: [
        { provide: PRODUCT_REQUEST_AUTH, useValue: options.requestAuth },
        { provide: DECLARATIONS, useValue: options.declarations },
        ProductRouteInventory,
        ProductRouteGuard,
        { provide: APP_GUARD, useExisting: ProductRouteGuard },
      ],
    };
  }
}
