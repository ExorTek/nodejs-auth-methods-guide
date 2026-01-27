class CustomError extends Error {
  constructor(message, statusCode, isOperational, code) {
    super(message);
    this.statusCode = statusCode || 500;
    this.isOperational = isOperational || true;
    this.code = code || 'INTERNAL_SERVER_ERROR';
    Error.captureStackTrace(this, this.constructor);
  }
}

export default CustomError;
