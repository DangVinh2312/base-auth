import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException } from '@nestjs/common';
import {
  ProductAuthenticationError,
  ProductAccessDenied,
  TransactionConflictError,
} from '@base-authorization/typeorm-postgres';
@Catch()
export class ProductErrorFilter implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost): void {
    const status =
      error instanceof HttpException
        ? error.getStatus()
        : error instanceof ProductAuthenticationError
          ? 401
          : error instanceof ProductAccessDenied
            ? 403
            : error instanceof TypeError
              ? 400
              : error instanceof TransactionConflictError
                ? 409
                : 503;
    const response = host
      .switchToHttp()
      .getResponse<{ status(code: number): { json(value: unknown): void } }>();
    response.status(status).json({
      statusCode: status,
      message:
        status === 401
          ? 'Authentication failed'
          : status === 403
            ? 'Access denied'
            : status === 404
              ? 'Not found'
              : status === 400
                ? 'Invalid request'
                : status === 409
                  ? 'Conflict'
                  : 'Unavailable',
    });
  }
}
