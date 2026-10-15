import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  Logger,
} from '@nestjs/common';
import {
  ProductAuthenticationError,
  ProductAccessDenied,
  ProductInvalidRequest,
  TransactionConflictError,
} from '@base-authorization/typeorm-postgres';

const logger = new Logger('ProductErrorFilter');
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
            : error instanceof ProductInvalidRequest
              ? 400
              : error instanceof TransactionConflictError
                ? 409
                : 503;
    // Unexpected faults stay diagnosable without leaking input: messages and driver details
    // (query, parameters, detail) may carry secrets or PII, so only type, SQLSTATE and frames.
    // Deliberate HTTP responses (e.g. 503 for an unconfigured capability) are not faults.
    if (status >= 500 && !(error instanceof HttpException)) {
      const e = error instanceof Error ? error : undefined;
      const code = (error as { code?: unknown } | null)?.code;
      logger.error(
        `${e?.constructor.name ?? typeof error}${typeof code === 'string' ? ` ${code}` : ''}`,
        // Frames follow the header, which repeats name and message (possibly multi-line).
        e?.stack
          ?.split('\n')
          .slice(String(e).split('\n').length)
          .filter((line) => /^\s+at /.test(line))
          .join('\n'),
      );
    }
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
