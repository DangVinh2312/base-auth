import { productOpenApi } from './openapi.js';
import type { ProductPage, ProductRow } from '@base-authorization/typeorm-postgres';
import {
  Body,
  Inject,
  HttpCode,
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Query,
  Req,
  Res,
  ServiceUnavailableException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ProductPublic, ProductAuthenticated, ProductAuthorize } from '@base-authorization/nest';
import { PRODUCT_HTTP_SERVICES, type ProductHttpServices } from './http-services.js';
import {
  type HttpRequest,
  type HttpResponse,
  enforceCsrf,
  bodyFields,
  newCsrf,
  setCookie,
  cookieName,
  cookies,
  sessionSecret,
} from './http-security.js';
@Controller()
export class ProductController {
  constructor(@Inject(PRODUCT_HTTP_SERVICES) private readonly runtime: ProductHttpServices) {}
  @Get('openapi.json')
  @ProductPublic()
  openapi() {
    return productOpenApi;
  }
  @Get('health/metrics')
  @ProductPublic()
  metrics() {
    return this.runtime.metrics.snapshot();
  }
  @Get('auth/csrf')
  @ProductPublic()
  csrf(@Res({ passthrough: true }) res: HttpResponse) {
    const csrfToken = newCsrf();
    setCookie(res, this.runtime.config, 'csrf', csrfToken, 3600);
    return { csrfToken };
  }
  @HttpCode(200)
  @Post('auth/login')
  @ProductPublic()
  async login(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.runtime.config);
    if (!this.runtime.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['email', 'password']);
    const session = await this.runtime.identity.login(
      dto.email!,
      dto.password!,
      req.ip || 'unknown',
    );
    setCookie(res, this.runtime.config, 'session', session.secret, 43200);
    return { expiresAt: session.expiresAt.toISOString() };
  }
  @HttpCode(200)
  @Post('auth/activate')
  @ProductPublic()
  async activate(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.runtime.config);
    if (!this.runtime.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['token', 'password']);
    await this.runtime.identity.activate(dto.token!, dto.password!, req.ip || 'unknown');
    return { status: 'activated' };
  }
  @HttpCode(200)
  @Post('auth/reauthenticate')
  @ProductAuthenticated()
  async reauthenticate(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.runtime.config);
    if (!this.runtime.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['password']);
    const session = await this.runtime.identity.reauthenticate(
      sessionSecret(req, this.runtime.config),
      dto.password!,
      req.ip || 'unknown',
    );
    setCookie(
      res,
      this.runtime.config,
      'session',
      session.secret,
      Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000)),
    );
    return { expiresAt: session.expiresAt.toISOString() };
  }
  @Get('auth/session')
  @ProductAuthenticated()
  async current(@Req() req: HttpRequest) {
    const session = await this.runtime.currentSession(sessionSecret(req, this.runtime.config));
    return { userId: session.userId, method: session.method, assurance: session.assurance };
  }
  @HttpCode(200)
  @Post('auth/logout')
  @ProductAuthenticated()
  async logout(@Req() req: HttpRequest, @Res({ passthrough: true }) res: HttpResponse) {
    enforceCsrf(req, this.runtime.config);
    await this.runtime.identity.logout(sessionSecret(req, this.runtime.config));
    setCookie(res, this.runtime.config, 'session', '', 0);
    return { status: 'revoked' };
  }
  @HttpCode(200)
  @Post('auth/recovery/request')
  @ProductPublic()
  async requestReset(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.runtime.config);
    if (!this.runtime.config.localEnabled || !this.runtime.recoveryDelivery)
      throw new ServiceUnavailableException();
    const dto = bodyFields(body, ['email']);
    const result = await this.runtime.identity.requestPasswordReset(
      dto.email!,
      req.ip || 'unknown',
    );
    if (result) await this.runtime.recoveryDelivery(result.userId, result.token);
    return { status: 'accepted' };
  }
  @HttpCode(200)
  @Post('auth/recovery/reset')
  @ProductPublic()
  async reset(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.runtime.config);
    if (!this.runtime.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['token', 'password']);
    await this.runtime.identity.resetPassword(dto.token!, dto.password!, req.ip || 'unknown');
    return { status: 'reset' };
  }
  @HttpCode(200)
  @Post('auth/password')
  @ProductAuthenticated()
  async password(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.runtime.config);
    if (!this.runtime.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['currentPassword', 'password']);
    await this.runtime.identity.changePassword(
      sessionSecret(req, this.runtime.config),
      dto.currentPassword!,
      dto.password!,
      req.ip || 'unknown',
    );
    return { status: 'changed' };
  }
  @HttpCode(200)
  @Post('auth/oidc/begin')
  @ProductPublic()
  async oidcBegin(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.runtime.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.runtime.config, 'browser', browser, 600);
    const result = await this.runtime.oidc.begin(
      dto.issuer!,
      browser,
      { purpose: 'login' },
      req.ip || 'unknown',
    );
    return { authorizationUrl: result };
  }
  @Get('auth/oidc/callback')
  @ProductPublic()
  async callback(
    @Req() req: HttpRequest,
    @Query('iss') issuer: string,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    const browser = cookies(req)[cookieName(this.runtime.config, 'browser')] || '';
    const session = await this.runtime.oidc.callback(
      issuer,
      new URL(req.originalUrl, this.runtime.config.origin),
      browser,
      sessionSecret(req, this.runtime.config) || undefined,
    );
    setCookie(res, this.runtime.config, 'browser', '', 0);
    if (session)
      setCookie(
        res,
        this.runtime.config,
        'session',
        session.secret,
        Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000)),
      );
    return { status: session ? 'authenticated' : 'linked' };
  }
  @HttpCode(200)
  @Post('auth/oidc/link')
  @ProductAuthenticated()
  async link(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.runtime.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.runtime.config, 'browser', browser, 600);
    return {
      authorizationUrl: await this.runtime.oidc.begin(
        dto.issuer!,
        browser,
        { purpose: 'link', sessionSecret: sessionSecret(req, this.runtime.config) },
        req.ip || 'unknown',
      ),
    };
  }
  @HttpCode(200)
  @Post('auth/oidc/unlink')
  @ProductAuthenticated()
  async unlink(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.runtime.config);
    const dto = bodyFields(body, ['issuer', 'subject']);
    await this.runtime.oidc.unlink(
      sessionSecret(req, this.runtime.config),
      dto.issuer!,
      dto.subject!,
    );
    return { status: 'unlinked' };
  }
  @HttpCode(200)
  @Post('auth/logout-all')
  @ProductAuthenticated()
  async logoutAll(@Req() req: HttpRequest, @Res({ passthrough: true }) res: HttpResponse) {
    enforceCsrf(req, this.runtime.config);
    await this.runtime.identity.logout(sessionSecret(req, this.runtime.config), true);
    setCookie(res, this.runtime.config, 'session', '', 0);
    return { status: 'revoked' };
  }
  @HttpCode(200)
  @Post('auth/oidc/activate')
  @ProductPublic()
  async oidcActivate(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.runtime.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.runtime.config, 'browser', browser, 600);
    return {
      authorizationUrl: await this.runtime.oidc.begin(
        dto.issuer!,
        browser,
        { purpose: 'activation' },
        req.ip || 'unknown',
      ),
    };
  }
  @HttpCode(200)
  @Post('auth/oidc/reauthenticate')
  @ProductAuthenticated()
  async oidcReauthenticate(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.runtime.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.runtime.config, 'browser', browser, 600);
    return {
      authorizationUrl: await this.runtime.oidc.begin(
        dto.issuer!,
        browser,
        { purpose: 'reauth', sessionSecret: sessionSecret(req, this.runtime.config) },
        req.ip || 'unknown',
      ),
    };
  }
  @Get('documents')
  @ProductAuthorize('document', 'read')
  list(@Req() req: HttpRequest): Promise<ProductPage> {
    return this.runtime.authorization.list(
      sessionSecret(req, this.runtime.config),
      'document',
      'read',
    );
  }
  @Get('documents/:id')
  @ProductAuthorize('document', 'read')
  async detail(@Req() req: HttpRequest, @Param('id') id: string): Promise<ProductRow> {
    const result = await this.runtime.authorization.detail(
      sessionSecret(req, this.runtime.config),
      'document',
      'read',
      id,
    );
    if (!result) throw new NotFoundException();
    return result;
  }
  @Patch('documents/:id')
  @ProductAuthorize('document', 'update')
  async update(@Req() req: HttpRequest, @Param('id') id: string, @Body() body: unknown) {
    enforceCsrf(req, this.runtime.config);
    const dto = bodyFields(body, ['title']);
    if (!dto.title?.trim() || Buffer.byteLength(dto.title) > 500) throw new NotFoundException();
    if (
      !(await this.runtime.authorization.update(
        sessionSecret(req, this.runtime.config),
        'document',
        'update',
        id,
        dto,
      ))
    )
      throw new NotFoundException();
    return { status: 'updated' };
  }
  @HttpCode(200)
  @Post('administration/users/:id/suspend')
  @ProductAuthorize('account', 'suspend')
  async suspend(@Req() req: HttpRequest, @Param('id') id: string) {
    enforceCsrf(req, this.runtime.config);
    if (
      !(await this.runtime.authorization.suspendUser(sessionSecret(req, this.runtime.config), id))
    )
      throw new NotFoundException();
    return { status: 'suspended' };
  }
}
