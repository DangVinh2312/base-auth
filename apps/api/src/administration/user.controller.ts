import { ProductAuthorize } from '../authorization/enforcement/product-authorization.module.js';
import { Controller, HttpCode, Inject, NotFoundException, Param, Post, Req } from '@nestjs/common';
import {
  type HttpRequest,
  enforceCsrf,
  sessionSecret,
} from '../infrastructure/http-security.helper.js';
import {
  ADMINISTRATION_HTTP_PORT,
  type AdministrationHttpPort,
} from './administration.http-port.js';

@Controller('administration/users')
export class UserController {
  constructor(
    @Inject(ADMINISTRATION_HTTP_PORT) private readonly administration: AdministrationHttpPort,
  ) {}

  @HttpCode(200)
  @Post(':id/suspend')
  @ProductAuthorize('account', 'suspend')
  async suspend(@Req() req: HttpRequest, @Param('id') id: string) {
    enforceCsrf(req, this.administration.config);
    if (
      !(await this.administration.suspendUser(sessionSecret(req, this.administration.config), id))
    )
      throw new NotFoundException();
    return { status: 'suspended' };
  }
}
