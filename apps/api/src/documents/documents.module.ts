import { Module } from '@nestjs/common';
import { DocumentsController } from './documents.controller.js';

/** Needs DOCUMENTS_HTTP_PORT; AppModule supplies the runtime module that exports it. */
@Module({ controllers: [DocumentsController] })
export class DocumentsModule {}
