import { Controller, Get } from '@nestjs/common';
import { ProductPublic } from '@base-authorization/nest';
import { productOpenApi } from './product-openapi.js';
@Controller()
export class OpenApiController {
  @Get('openapi.json')
  @ProductPublic()
  openapi() {
    return productOpenApi;
  }
}
