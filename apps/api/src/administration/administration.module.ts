import { Module } from '@nestjs/common';
import { UsersController } from './users.controller.js';
/** Needs ADMINISTRATION_HTTP_PORT; AppModule supplies the runtime module that exports it. */
@Module({ controllers: [UsersController] })
export class AdministrationModule {}
