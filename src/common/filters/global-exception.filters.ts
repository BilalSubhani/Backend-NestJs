import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { ResponseUtil } from '../utils/response.util';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        message = exceptionResponse;
      } else if (
        typeof exceptionResponse === 'object' &&
        exceptionResponse['message']
      ) {
        message = Array.isArray(exceptionResponse['message'])
          ? exceptionResponse['message'].join(', ')
          : exceptionResponse['message'];
      }
    }

    const errorMessages = {
      [HttpStatus.BAD_REQUEST]: message || 'Invalid request data',
      [HttpStatus.UNAUTHORIZED]: 'Authentication required',
      [HttpStatus.FORBIDDEN]: 'Access denied',
      [HttpStatus.NOT_FOUND]: message || 'Resource not found',
      [HttpStatus.CONFLICT]: 'Resource already exists',
      [HttpStatus.UNPROCESSABLE_ENTITY]: 'Validation failed',
      [HttpStatus.TOO_MANY_REQUESTS]: 'Too many requests',
      [HttpStatus.INTERNAL_SERVER_ERROR]: 'Something went wrong on our end',
    };

    const finalMessage = errorMessages[status] || message;

    response.status(status).json(ResponseUtil.error(finalMessage));
  }
}
