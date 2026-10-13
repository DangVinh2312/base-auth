import { timingSafeEqual, randomBytes } from 'node:crypto';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import type { AppConfig } from './config.js';
export interface HttpRequest {
  headers: Record<string, string | undefined>;
  ip?: string;
  originalUrl: string;
}
export interface HttpResponse {
  append(name: string, value: string): void;
  redirect(status: number, url: string): void;
}
export function cookies(request: HttpRequest): Record<string, string> {
  const raw = request.headers.cookie || '';
  if (raw.length > 8192) throw new BadRequestException();
  const result: Record<string, string> = {};
  for (const item of raw.split(';')) {
    if (!item.trim()) continue;
    const index = item.indexOf('=');
    if (index < 1) throw new BadRequestException();
    const key = item.slice(0, index).trim();
    if (Object.hasOwn(result, key)) throw new BadRequestException();
    result[key] = item.slice(index + 1).trim();
  }
  return result;
}
export const cookieName = (
  config: Pick<AppConfig, 'origin'>,
  key: 'session' | 'csrf' | 'browser',
) => `${config.origin.protocol === 'https:' ? '__Host-' : ''}authz_${key}`;
export function setCookie(
  res: HttpResponse,
  config: Pick<AppConfig, 'origin'>,
  key: 'session' | 'csrf' | 'browser',
  value: string,
  maxAge: number,
): void {
  res.append(
    'Set-Cookie',
    `${cookieName(config, key)}=${value}; Path=/; Max-Age=${maxAge}; SameSite=Lax${key !== 'csrf' ? '; HttpOnly' : ''}${config.origin.protocol === 'https:' ? '; Secure' : ''}`,
  );
}
export function sessionSecret(req: HttpRequest, config: Pick<AppConfig, 'origin'>): string {
  return cookies(req)[cookieName(config, 'session')] || '';
}
export function enforceCsrf(req: HttpRequest, config: Pick<AppConfig, 'origin'>): void {
  const token = req.headers['x-csrf-token'];
  const stored = cookies(req)[cookieName(config, 'csrf')];
  if (
    req.headers.origin !== config.origin.origin ||
    !token ||
    !stored ||
    !/^[A-Za-z0-9_-]{43}$/.test(token) ||
    token.length !== stored.length ||
    !timingSafeEqual(Buffer.from(token), Buffer.from(stored))
  )
    throw new ForbiddenException();
}
export function newCsrf(): string {
  return randomBytes(32).toString('base64url');
}
export function bodyFields(value: unknown, keys: readonly string[]): Record<string, string> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).some((k) => !keys.includes(k)) ||
    keys.some(
      (k) =>
        !Object.hasOwn(value, k) ||
        typeof (value as Record<string, unknown>)[k] !== 'string' ||
        (value as Record<string, string>)[k]!.length > 2048,
    )
  )
    throw new BadRequestException();
  return value as Record<string, string>;
}
