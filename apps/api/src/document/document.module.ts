import { Module } from '@nestjs/common';
import { DocumentController } from './document.controller.js';

/** Needs DOCUMENT_HTTP_PORT; AppModule supplies the runtime module that exports it. */
@Module({ controllers: [DocumentController] })
export class DocumentModule {}
