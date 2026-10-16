import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Controller, Get, Module, UnauthorizedException } from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host.js';
import * as authorization from '../../apps/api/dist/authorization/enforcement/product-authorization.module.js';

const declarations = { resources: { item: { actions: { read: {} } } } };
const requestAuth = { authenticate: async () => {} };

async function boot(controller: new () => object) {
  class FixtureModule {}
  Module({
    imports: [authorization.ProductAuthorizationModule.register({ declarations, requestAuth })],
    controllers: [controller],
  })(FixtureModule);
  return NestFactory.createApplicationContext(FixtureModule, {
    logger: false,
    abortOnError: false,
  });
}

function route() {
  class FixtureController {
    read(this: void) {
      return 'fixture';
    }
  }
  Controller('fixture')(FixtureController);
  const descriptor = Object.getOwnPropertyDescriptor(FixtureController.prototype, 'read')!;
  Get()(FixtureController.prototype, 'read', descriptor);
  return { controller: FixtureController, descriptor };
}

test('product route authorization module exists', () => {
  assert.equal(typeof authorization.ProductAuthorizationModule, 'function');
});

test('Nest startup refuses an unclassified controller route', async () => {
  await assert.rejects(boot(route().controller), /classification/);
});

test('Nest startup accepts explicitly public routes including inherited handlers', async () => {
  const fixture = route();
  authorization.ProductPublic()(fixture.controller.prototype, 'read', fixture.descriptor);
  class ChildController extends fixture.controller {}
  Controller('child')(ChildController);
  const app = await boot(ChildController);
  await app.close();
});

test('Nest startup refuses ambiguous metadata and unknown permission declarations', async () => {
  const ambiguous = route();
  authorization.ProductPublic()(ambiguous.controller.prototype, 'read', ambiguous.descriptor);
  authorization.ProductAuthenticated()(
    ambiguous.controller.prototype,
    'read',
    ambiguous.descriptor,
  );
  await assert.rejects(boot(ambiguous.controller), /classification/);
  const unknown = route();
  authorization.ProductAuthorize('item', 'remove')(
    unknown.controller.prototype,
    'read',
    unknown.descriptor,
  );
  await assert.rejects(boot(unknown.controller), /permission/);
});

test('global guard validates sessions for both protected classifications and leaves public explicit', async () => {
  const request = { headers: { cookie: 'fixture' } };
  let checks = 0;
  let invalid = false;
  const guard = new authorization.ProductRouteGuard(new Reflector(), {
    authenticate: (received) => {
      assert.equal(received, request);
      checks += 1;
      if (invalid) return Promise.reject(new UnauthorizedException());
      return Promise.resolve();
    },
  });
  for (const decorator of [
    authorization.ProductAuthenticated(),
    authorization.ProductAuthorize('item', 'read'),
  ]) {
    const fixture = route();
    decorator(fixture.controller.prototype, 'read', fixture.descriptor);
    const context = new ExecutionContextHost(
      [request],
      fixture.controller,
      fixture.controller.prototype.read,
    );
    assert.equal(await guard.canActivate(context), true);
    invalid = true;
    await assert.rejects(guard.canActivate(context), UnauthorizedException);
    invalid = false;
  }
  assert.equal(checks, 4);
  const fixture = route();
  authorization.ProductPublic()(fixture.controller.prototype, 'read', fixture.descriptor);
  const context = new ExecutionContextHost(
    [request],
    fixture.controller,
    fixture.controller.prototype.read,
  );
  assert.equal(await guard.canActivate(context), true);
  assert.equal(checks, 4);
  context.setType('ws');
  await assert.rejects(guard.canActivate(context));
  const missing = route();
  await assert.rejects(
    guard.canActivate(
      new ExecutionContextHost([request], missing.controller, missing.controller.prototype.read),
    ),
  );
});

test('route inventory fails before any application bootstrap hook, however deep its module', async () => {
  // Nest runs onApplicationBootstrap deepest module first; a bootstrap with effects (manifest
  // sync, readiness) in a module nested below the controllers must still never start.
  const calls: string[] = [];
  class DeepService {
    onApplicationBootstrap() {
      calls.push('deep bootstrap');
    }
  }
  class DeepModule {}
  Module({ providers: [DeepService], exports: [DeepService] })(DeepModule);
  class FeatureModule {}
  Module({ imports: [DeepModule], controllers: [route().controller] })(FeatureModule);
  class RootModule {}
  Module({
    imports: [
      authorization.ProductAuthorizationModule.register({ declarations, requestAuth }),
      FeatureModule,
    ],
  })(RootModule);
  await assert.rejects(
    NestFactory.createApplicationContext(RootModule, { logger: false, abortOnError: false }),
    /classification/,
  );
  assert.deepEqual(calls, []);
});
