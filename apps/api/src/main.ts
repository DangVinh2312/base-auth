import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { ConfigError, loadConfig } from './config.js';
import { ProductRuntime } from './product-runtime.js';
let runtime: ProductRuntime | undefined;
try {
  const config = loadConfig(process.env);
  runtime = await ProductRuntime.create(config);
  const app = await NestFactory.create(AppModule.register(runtime), {
    logger: config.logLevels,
    abortOnError: false,
  });
  app.use(
    (
      _request: unknown,
      response: { setHeader(name: string, value: string): void },
      next: () => void,
    ) => {
      response.setHeader('Cache-Control', 'no-store');
      response.setHeader('Referrer-Policy', 'no-referrer');
      response.setHeader('X-Content-Type-Options', 'nosniff');
      next();
    },
  );
  app.enableShutdownHooks();
  await app.listen(config.port);
} catch (error) {
  await runtime?.onApplicationShutdown();
  console.error(error instanceof ConfigError ? error.message : 'Application startup failed');
  process.exitCode = 1;
}
