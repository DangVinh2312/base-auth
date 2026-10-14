import { ProductAuthenticated, ProductPublic } from '@base-authorization/nest';
import { Body, Controller, Get, HttpCode, Inject, Post, Query, Req, Res } from '@nestjs/common';
import {
  type HttpRequest,
  type HttpResponse,
  bodyFields,
  cookieName,
  cookies,
  enforceCsrf,
  newCsrf,
  sessionSecret,
  setCookie,
} from '../infrastructure/http-security.js';
import { AUTH_HTTP_PORT, type AuthHttpPort } from './auth.http-port.js';
@Controller('auth/oidc')
export class OidcController {
  constructor(@Inject(AUTH_HTTP_PORT) private readonly auth: AuthHttpPort) {}
  @HttpCode(200)
  @Post('begin')
  @ProductPublic()
  async oidcBegin(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.auth.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.auth.config, 'browser', browser, 600);
    const result = await this.auth.oidc.begin(
      dto.issuer!,
      browser,
      { purpose: 'login' },
      req.ip || 'unknown',
    );
    return { authorizationUrl: result };
  }
  @Get('callback')
  @ProductPublic()
  async callback(
    @Req() req: HttpRequest,
    @Query('iss') issuer: string,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    const browser = cookies(req, this.auth.config)[cookieName(this.auth.config, 'browser')] || '';
    const session = await this.auth.oidc.callback(
      issuer,
      new URL(req.originalUrl, this.auth.config.origin),
      browser,
      sessionSecret(req, this.auth.config) || undefined,
    );
    setCookie(res, this.auth.config, 'browser', '', 0);
    if (session)
      setCookie(
        res,
        this.auth.config,
        'session',
        session.secret,
        Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000)),
      );
    return { status: session ? 'authenticated' : 'linked' };
  }
  @HttpCode(200)
  @Post('link')
  @ProductAuthenticated()
  async link(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.auth.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.auth.config, 'browser', browser, 600);
    return {
      authorizationUrl: await this.auth.oidc.begin(
        dto.issuer!,
        browser,
        { purpose: 'link', sessionSecret: sessionSecret(req, this.auth.config) },
        req.ip || 'unknown',
      ),
    };
  }
  @HttpCode(200)
  @Post('unlink')
  @ProductAuthenticated()
  async unlink(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.auth.config);
    const dto = bodyFields(body, ['issuer', 'subject']);
    await this.auth.oidc.unlink(sessionSecret(req, this.auth.config), dto.issuer!, dto.subject!);
    return { status: 'unlinked' };
  }
  @HttpCode(200)
  @Post('activate')
  @ProductPublic()
  async oidcActivate(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.auth.config);
    const dto = bodyFields(body, ['issuer', 'token']);
    const browser = newCsrf();
    setCookie(res, this.auth.config, 'browser', browser, 600);
    return {
      authorizationUrl: await this.auth.oidc.begin(
        dto.issuer!,
        browser,
        { purpose: 'activation', activationToken: dto.token! },
        req.ip || 'unknown',
      ),
    };
  }
  @HttpCode(200)
  @Post('reauthenticate')
  @ProductAuthenticated()
  async oidcReauthenticate(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.auth.config);
    const dto = bodyFields(body, ['issuer']);
    const browser = newCsrf();
    setCookie(res, this.auth.config, 'browser', browser, 600);
    return {
      authorizationUrl: await this.auth.oidc.begin(
        dto.issuer!,
        browser,
        { purpose: 'reauth', sessionSecret: sessionSecret(req, this.auth.config) },
        req.ip || 'unknown',
      ),
    };
  }
}
