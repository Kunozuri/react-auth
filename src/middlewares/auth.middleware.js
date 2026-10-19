// src/middlewares/error.middleware.js
//
// The ONE place where errors become HTTP responses.
// Every `throw new ApiError(...)` and every failed `await` ends up here (via asyncHandler -> next(err)).
//
// Express recognises an error middleware by its FOUR parameters (err, req, res, next).
// Even if you don't use `next`, it must be there, or Express treats this as a normal middleware.
import { NODE_ENV } from '../config/env.js';

const errorMiddleware = (err, req, res, next) => {
    // If a response was already partly sent, we can't send another one. Let Express close the connection.
    if (res.headersSent) {
        return next(err);
    }

    // Errors made with ApiError carry their own statusCode.
    // Anything else (a bug, a database crash) has none, so it is a 500 = Internal Server Error.
    let statusCode = err.statusCode || 500;
    let message = err.message || 'Server error';

    // --- Translate known library errors into proper client errors ---

    // Mongoose: the model's validation failed (bad email format, too short, wrong enum...). Client's fault -> 400.
    if (err.name === 'ValidationError') {
        statusCode = 400;
        message = Object.values(err.errors).map((e) => e.message).join(', ');
    }
        // MongoDB: a unique index was violated (code 11000). This catches the rare race where two people
    // sign up with the same email at the same moment, after our findOne check already passed. -> 409.
    else if (err.code === 11000) {
        statusCode = 409;
        const field = Object.keys(err.keyValue || {})[0] || 'value';
        message = `${field} already in use`;
    }
    // Mongoose: an id like "abc" can't be cast to an ObjectId -> 400.
    else if (err.name === 'CastError') {
        statusCode = 400;
        message = `Invalid ${err.path}`;
    }
    // jsonwebtoken: bad signature, malformed or expired token -> 401.
    else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        statusCode = 401;
        message = 'Invalid or expired token';
    }

    // 5xx means OUR bug, so log it for yourself. 4xx are normal "you sent something wrong" cases, no need to spam the log.
    if (statusCode >= 500) {
        console.error(err);
        // Never leak internal details (database messages, file paths) to the client in production.
        if (NODE_ENV === 'production') {
            message = 'Something went wrong on the server';
        }
    }

    res.status(statusCode).json({
        success: false,
        message,
        // The stack trace helps you while developing, but must never be sent in production.
        ...(NODE_ENV === 'development' && statusCode >= 500 && { stack: err.stack }),
    });
};

export default errorMiddleware;