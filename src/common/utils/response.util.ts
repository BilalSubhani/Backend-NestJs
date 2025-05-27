import { ApiResponse } from '../interfaces/api-response.interface';

export class ResponseUtil {
  static success<T>(message: string, data: T = null): ApiResponse<T> {
    return {
      status: 1,
      message,
      data,
    };
  }
  static error(message: string, data: any = null): ApiResponse<null> {
    return {
      status: 0,
      message,
      data,
    };
  }
}
