// src/utils/ApiError.js
//
// A custom error that carries an HTTP status code.
// Before, you wrote this every time:
//
//     const error = new Error('Email already in use');
//     error.statusCode = 409;
//     throw error;
//
// Now it is one line:
//
//     throw new ApiError(409, 'Email already in use');
//
// `extends Error` means it IS a normal JavaScript error (it has .message and .stack),
// we just add a statusCode on top. Your error middleware reads err.statusCode, exactly like before.
class ApiError extends Error {
    constructor(statusCode, message) {
        super(message);              // sets this.message
        this.name = 'ApiError';      // shows up in logs, so you can tell it apart from other errors
        this.statusCode = statusCode;

        // Keeps the stack trace clean: it starts where you wrote `new ApiError(...)`,
        // not inside this constructor.
        Error.captureStackTrace(this, this.constructor);
    }
}

export default ApiError;