import { Response } from 'express';

class CustomResponse {
  static successResponse(res: Response, message: string, statusCode: number, data: any = {}) {
    return res.status(statusCode).json({
      message,
      success: true,
      status: statusCode,
      data,
    });
  }

  static errorResponse(res: Response, message: string, statusCode: number, data: any = {}) {
    return res.status(statusCode).json({
      message,
      success: false,
      status: statusCode,
      data,
    });
  }
}

export default CustomResponse;
