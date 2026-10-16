import { Controller, Get } from '@nestjs/common';
import { ProductPublic } from '../authorization/enforcement/product-authorization.module.js';
import { productOpenApi } from './product-openapi.schema.js';

@Controller()
export class OpenApiController {
  @Get('openapi.json')
  @ProductPublic()
  openapi() {
    return productOpenApi;
  }
}
