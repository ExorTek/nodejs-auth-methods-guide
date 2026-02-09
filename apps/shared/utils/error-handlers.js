import { capitalizeFirstLetter, getDuplicateKeyErrorMessage } from './helpers.js';
import { DEFAULT_ERROR_CODE, DEFAULT_ERROR_MESSAGE, PUBLIC_ERROR_CODES } from '../constants/index.js';
import logger from './logger.js';
import CustomError from './CustomError.js';

const defaultMessages = {
  SyntaxError:
    'We have encountered a syntax error in your request. Please ensure that your request is properly formatted and try again.',
  TypeError:
    'There was a type error in your request. Please check the data types of the values you provided and try again.',
  CastError: 'The data provided could not be converted to the required type. Please verify your input and try again.',
  ReferenceError:
    'There was a reference error in your request. Please ensure that all variables and references are correctly defined and try again.',
  StrictPopulateError: 'We encountered an error while populating data. Please check your request and try again.',
  RangeError:
    'We encountered a range error in your request. Please ensure that all values are within the acceptable range and try again.',
  MissingSchemaError: 'The requested schema is missing. Please verify your request and try again.',
  ValidationError: 'There was a validation error with your input. Please check the provided data and try again.',
  MongoServerError:
    'A database error occurred while processing your request. Please try again later or contact support if the issue persists.',
};

/** JWT library error name → { statusCode, message, code } */
const jwtErrorMap = {
  TokenExpiredError: { statusCode: 401, message: 'Access token expired', code: 'TOKEN_EXPIRED' },
  JsonWebTokenError: { statusCode: 401, message: 'Invalid access token', code: 'INVALID_TOKEN' },
  NotBeforeError: { statusCode: 401, message: 'Access token not yet active', code: 'TOKEN_NOT_ACTIVE' },
};

const expressErrorHandler = (err, req, res, next) => {
  logger.error(err);

  let customError = err;

  // CORS error
  if (err.message === 'Invalid origin') {
    customError = new CustomError(
      'You are not allowed to access this resource!',
      403,
      true,
      PUBLIC_ERROR_CODES.FORBIDDEN,
    );
  }

  // JWT errors (TokenExpiredError, JsonWebTokenError, NotBeforeError)
  if (err.name in jwtErrorMap) {
    const mapped = jwtErrorMap[err.name];
    customError = new CustomError(mapped.message, mapped.statusCode, true, mapped.code);
  }

  // Default error messages for common error types
  if (err.name in defaultMessages) {
    customError = new CustomError(defaultMessages[err.name], 400, true, err.name.toUpperCase());
  }

  // MongoDB duplicate key error
  if (err.code === 11000) {
    customError = new CustomError(
      getDuplicateKeyErrorMessage(err.message, err.keyValue),
      400,
      true,
      PUBLIC_ERROR_CODES.DUPLICATE_KEY,
    );
  }

  // Validation errors
  if (err.errors) {
    let customErrorMessage = '';
    if (err.params?.spec) {
      customErrorMessage = capitalizeFirstLetter(err.errors[0]);
    } else {
      const errorMessage = err.message.includes('Cast to [ObjectId]')
        ? `Invalid argument: ${err.message.split('"')[1]}`
        : err.errors[Object.keys(err.errors)[0]].message;
      if (errorMessage.includes('BSONError')) {
        customErrorMessage = `Invalid argument: ${errorMessage.split('"')[1]}`;
      } else {
        customErrorMessage = errorMessage;
      }
    }
    customError = new CustomError(customErrorMessage, 400, true, PUBLIC_ERROR_CODES.VALIDATION_ERROR);
  }

  const response = {
    success: false,
    statusCode: customError.statusCode || 500,
    error: {
      code: customError.code || DEFAULT_ERROR_CODE,
      message: customError.message || DEFAULT_ERROR_MESSAGE,
    },
    meta: {
      requestId: req.id,
      url: req.url,
      method: req.method,
      timestamp: new Date().toISOString(),
    },
  };

  return res.status(response.statusCode).json(response);
};

const fastifyErrorHandler = (error, request, reply) => {
  logger.error(error);

  let customError = error;

  // CORS error
  if (error.message === 'Invalid origin') {
    customError = new CustomError(
      'You are not allowed to access this resource!',
      403,
      true,
      PUBLIC_ERROR_CODES.FORBIDDEN,
    );
  }

  // JWT errors (TokenExpiredError, JsonWebTokenError, NotBeforeError)
  if (error.name in jwtErrorMap) {
    const mapped = jwtErrorMap[error.name];
    customError = new CustomError(mapped.message, mapped.statusCode, true, mapped.code);
  }

  // Default error messages for common error types
  if (error.name in defaultMessages) {
    customError = new CustomError(defaultMessages[error.name], 400, true, error.name.toUpperCase());
  }

  // MongoDB duplicate key error
  if (error.code === 11000) {
    customError = new CustomError(
      getDuplicateKeyErrorMessage(error.message, error.keyValue),
      400,
      true,
      PUBLIC_ERROR_CODES.DUPLICATE_KEY,
    );
  }

  // Validation errors
  if (error.errors) {
    let customErrorMessage = '';
    if (error.params?.spec) {
      customErrorMessage = capitalizeFirstLetter(error.errors[0]);
    } else {
      const errorMessage = error.message.includes('Cast to [ObjectId]')
        ? `Invalid argument: ${error.message.split('"')[1]}`
        : error.errors[Object.keys(error.errors)[0]].message;
      if (errorMessage.includes('BSONError')) {
        customErrorMessage = `Invalid argument: ${errorMessage.split('"')[1]}`;
      } else {
        customErrorMessage = errorMessage;
      }
    }
    customError = new CustomError(customErrorMessage, 400, true, PUBLIC_ERROR_CODES.VALIDATION_ERROR);
  }

  const response = {
    success: false,
    statusCode: customError.statusCode || 500,
    error: {
      code: customError.code || DEFAULT_ERROR_CODE,
      message: customError.message || DEFAULT_ERROR_MESSAGE,
    },
    meta: {
      requestId: request.id,
      path: request.url,
      method: request.method,
      timestamp: new Date().toISOString(),
    },
  };

  return reply.code(response.statusCode).send(response);
};

export { expressErrorHandler, fastifyErrorHandler };
