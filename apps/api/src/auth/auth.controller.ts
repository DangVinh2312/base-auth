import { ProductAuthenticated, ProductPublic } from '@base-authorization/nest';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  Inject,
  Logger,
  Post,
  Req,
  Res,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  type HttpRequest,
  type HttpResponse,
  bodyFields,
  enforceCsrf,
  newCsrf,
  sessionSecret,
  setCookie,
} from '../infrastructure/http-security.js';
import { AUTH_HTTP_PORT, type AuthHttpPort } from './auth.http-port.js';

const recoveryLogger = new Logger('ProductRecovery');
@Controller('auth')
export class AuthController {
  constructor(@Inject(AUTH_HTTP_PORT) private readonly auth: AuthHttpPort) {}

  @Get('csrf')
  @ProductPublic()
  csrf(@Res({ passthrough: true }) res: HttpResponse) {
    const csrfToken = newCsrf();
    setCookie(res, this.auth.config, 'csrf', csrfToken, 3600);
    return { csrfToken };
  }

  @HttpCode(200)
  @Post('login')
  @ProductPublic()
  async login(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.auth.config);
    if (!this.auth.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['email', 'password']);
    const session = await this.auth.identity.login(dto.email!, dto.password!, req.ip || 'unknown');
    setCookie(res, this.auth.config, 'session', session.secret, 43200);
    return { expiresAt: session.expiresAt.toISOString() };
  }

  @HttpCode(200)
  @Post('activate')
  @ProductPublic()
  async activate(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.auth.config);
    if (!this.auth.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['token', 'password']);
    await this.auth.identity.activate(dto.token!, dto.password!, req.ip || 'unknown');
    return { status: 'activated' };
  }

  @HttpCode(200)
  @Post('reauthenticate')
  @ProductAuthenticated()
  async reauthenticate(
    @Body() body: unknown,
    @Req() req: HttpRequest,
    @Res({ passthrough: true }) res: HttpResponse,
  ) {
    enforceCsrf(req, this.auth.config);
    if (!this.auth.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['password']);
    const session = await this.auth.identity.reauthenticate(
      sessionSecret(req, this.auth.config),
      dto.password!,
      req.ip || 'unknown',
    );
    setCookie(
      res,
      this.auth.config,
      'session',
      session.secret,
      Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000)),
    );
    return { expiresAt: session.expiresAt.toISOString() };
  }

  @Get('session')
  @ProductAuthenticated()
  async current(@Req() req: HttpRequest) {
    const session = await this.auth.currentSession(sessionSecret(req, this.auth.config));
    return { userId: session.userId, method: session.method, assurance: session.assurance };
  }

  @HttpCode(200)
  @Post('logout')
  @ProductAuthenticated()
  async logout(@Req() req: HttpRequest, @Res({ passthrough: true }) res: HttpResponse) {
    enforceCsrf(req, this.auth.config);
    await this.auth.identity.logout(sessionSecret(req, this.auth.config));
    setCookie(res, this.auth.config, 'session', '', 0);
    return { status: 'revoked' };
  }

  @HttpCode(200)
  @Post('recovery/request')
  @ProductPublic()
  async requestReset(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.auth.config);
    if (!this.auth.config.localEnabled || !this.auth.recoveryDelivery)
      throw new ServiceUnavailableException();
    const dto = bodyFields(body, ['email']);
    const result = await this.auth.identity.requestPasswordReset(dto.email!, req.ip || 'unknown');
    // Delivery runs detached: its latency or failure must not reveal whether the account exists.
    if (result)
      void Promise.resolve()
        .then(() => this.auth.recoveryDelivery!(result.userId, result.token))
        .catch(() => recoveryLogger.warn('Recovery delivery failed'));
    return { status: 'accepted' };
  }

  @HttpCode(200)
  @Post('recovery/reset')
  @ProductPublic()
  async reset(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.auth.config);
    if (!this.auth.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['token', 'password']);
    await this.auth.identity.resetPassword(dto.token!, dto.password!, req.ip || 'unknown');
    return { status: 'reset' };
  }

  @HttpCode(200)
  @Post('password')
  @ProductAuthenticated()
  async password(@Body() body: unknown, @Req() req: HttpRequest) {
    enforceCsrf(req, this.auth.config);
    if (!this.auth.config.localEnabled) throw new UnauthorizedException();
    const dto = bodyFields(body, ['currentPassword', 'password']);
    await this.auth.identity.changePassword(
      sessionSecret(req, this.auth.config),
      dto.currentPassword!,
      dto.password!,
      req.ip || 'unknown',
    );
    return { status: 'changed' };
  }

  @HttpCode(200)
  @Post('logout-all')
  @ProductAuthenticated()
  async logoutAll(@Req() req: HttpRequest, @Res({ passthrough: true }) res: HttpResponse) {
    enforceCsrf(req, this.auth.config);
    await this.auth.identity.logout(sessionSecret(req, this.auth.config), true);
    setCookie(res, this.auth.config, 'session', '', 0);
    return { status: 'revoked' };
  }
}
