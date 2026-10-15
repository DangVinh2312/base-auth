import { Module } from '@nestjs/common';
import { UserController } from './user.controller.js';

/** Needs ADMINISTRATION_HTTP_PORT; AppModule supplies the runtime module that exports it. */
@Module({ controllers: [UserController] })
export class AdministrationModule {}
