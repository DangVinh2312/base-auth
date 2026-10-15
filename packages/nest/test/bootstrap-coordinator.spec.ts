import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { Inject, Injectable, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
  BootstrapModule,
  MANIFEST_SYNC,
  type ManifestSyncPort,
  ReadinessGate,
} from '@base-authorization/nest';

const tenants = ['00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b'];

function fakeSync(fail: string[] = []) {
  const done: string[] = [];
  const sync: ManifestSyncPort = {
    tenants: () => tenants,

    reconcile: async (tenant) => {
      await sleep(50);
      if (fail.includes(tenant)) throw new Error('release rejected (fixture)');
      done.push(tenant);
    },
  };
  return { sync, done };
}

test('initialisation (and therefore listen) waits for every tenant to reconcile; then ready', async () => {
  const { sync, done } = fakeSync();
  const app = await NestFactory.createApplicationContext(BootstrapModule.forRoot({ sync }), {
    logger: false,
  });
  try {
    assert.deepEqual(
      done,
      tenants,
      'reconcile completed before the application finished bootstrapping',
    );
    const gate = app.get(ReadinessGate);
    assert.equal(gate.ready, true);
    assert.ok(tenants.every((t) => gate.isTenantReady(t)));
  } finally {
    await app.close();
  }
});

test('a failed tenant sync keeps that tenant and the process not ready (fail closed)', async () => {
  const { sync } = fakeSync([tenants[1]!]);
  const app = await NestFactory.createApplicationContext(BootstrapModule.forRoot({ sync }), {
    logger: false,
  });
  try {
    const gate = app.get(ReadinessGate);
    assert.equal(gate.ready, false);
    assert.equal(gate.isTenantReady(tenants[0]!), true);
    assert.equal(gate.isTenantReady(tenants[1]!), false);
  } finally {
    await app.close();
  }
});

test('the sync port is not injectable outside the bootstrap module (no handler/controller access)', async () => {
  // Decorators applied by hand: tests run through Node type stripping, which has no decorators.
  class Handler {
    sync: ManifestSyncPort;

    constructor(sync: ManifestSyncPort) {
      this.sync = sync;
    }
  }
  Inject(MANIFEST_SYNC)(Handler, undefined, 0);
  Injectable()(Handler);
  class FeatureModule {}
  Module({ imports: [BootstrapModule.forRoot({ sync: fakeSync().sync })], providers: [Handler] })(
    FeatureModule,
  );
  await assert.rejects(
    NestFactory.createApplicationContext(FeatureModule, { logger: false, abortOnError: false }),
  );
});
