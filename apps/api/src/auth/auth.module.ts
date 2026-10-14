import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { OidcController } from './oidc.controller.js';
/** Needs AUTH_HTTP_PORT; AppModule supplies the runtime module that exports it. */
@Module({ controllers: [AuthController, OidcController] })
export class AuthModule {}
