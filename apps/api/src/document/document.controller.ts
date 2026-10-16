import { ProductAuthorize } from '../authorization/enforcement/product-authorization.module.js';
import type {
  Page as ProductPage,
  Row as ProductRow,
} from '../authorization/product-data.gateway.js';
import {
  Body,
  Controller,
  Get,
  Inject,
  NotFoundException,
  Param,
  Patch,
  Req,
} from '@nestjs/common';
import {
  type HttpRequest,
  bodyFields,
  enforceCsrf,
  sessionSecret,
} from '../infrastructure/http-security.helper.js';
import { DOCUMENT_HTTP_PORT, type DocumentHttpPort } from './document.http-port.js';

@Controller('documents')
export class DocumentController {
  constructor(@Inject(DOCUMENT_HTTP_PORT) private readonly documents: DocumentHttpPort) {}

  @Get()
  @ProductAuthorize('document', 'read')
  list(@Req() req: HttpRequest): Promise<ProductPage> {
    return this.documents.list(sessionSecret(req, this.documents.config));
  }

  @Get(':id')
  @ProductAuthorize('document', 'read')
  async detail(@Req() req: HttpRequest, @Param('id') id: string): Promise<ProductRow> {
    const result = await this.documents.detail(sessionSecret(req, this.documents.config), id);
    if (!result) throw new NotFoundException();
    return result;
  }

  @Patch(':id')
  @ProductAuthorize('document', 'update')
  async update(@Req() req: HttpRequest, @Param('id') id: string, @Body() body: unknown) {
    enforceCsrf(req, this.documents.config);
    const dto = bodyFields(body, ['title']);
    if (!dto.title?.trim() || Buffer.byteLength(dto.title) > 500) throw new NotFoundException();
    if (
      !(await this.documents.update(sessionSecret(req, this.documents.config), id, {
        title: dto.title,
      }))
    )
      throw new NotFoundException();
    return { status: 'updated' };
  }
}
