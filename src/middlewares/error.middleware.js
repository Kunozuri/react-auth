// We import NODE_ENV so we can behave differently in development vs production.
// (From src/middlewares/, "../config/env.js" goes up one folder, then into config/.)
import { NODE_ENV } from '../config/env.js';

// An error middleware is just a function with FOUR parameters.
// Express counts them: (err, req, res, next) is how it knows this is the error handler.
//   err  -> the error that was passed with next(error) or thrown in a route
//   req  -> the incoming request
//   res  -> the response we use to reply to the client
//   next -> required in the signature even if unused, otherwise Express won't treat this as an error handler
const errorMiddleware = (err, req, res, next) => {
    // If a response was already partly sent, we can't send a new one (it would crash with
    // "Cannot set headers after they are sent"). Hand the error to Express's built-in handler instead.
    // `return` stops our function here so nothing below runs.
    if (res.headersSent) {
        return next(err);
    }

    // Start with defaults. `||` means "use the left value if it exists, otherwise the right one".
    // Errors you create yourself carry err.statusCode (e.g. 401); unexpected errors don't, so they become 500.
    let statusCode = err.statusCode || 500;
    let message = err.message || 'Something went wrong';

    // ---------- Known error types: translate them into friendly responses ----------

    // 1) Duplicate key: MongoDB error code 11000, e.g. signing up with an email that already exists.
    if (err.code === 11000) {
        statusCode = 409; // 409 = Conflict
        // err.keyValue looks like { email: 'a@b.com' }. Object.keys(...)[0] grabs the field name ("email").
        const field = Object.keys(err.keyValue || {})[0] || 'field';
        message = `${field} already in use`;
    }

    // 2) Mongoose validation: a rule in your User model failed (match, minlength, required, enum...).
    if (err.name === 'ValidationError') {
        statusCode = 400; // 400 = Bad Request (the client sent bad data)
        // err.errors is an object with one entry per failed field.
        // Object.values(...) turns it into an array, .map(...) pulls out each message,
        // and .join(', ') glues them into one string like "Name is too short, Invalid email".
        message = Object.values(err.errors)
            .map((fieldError) => fieldError.message)
            .join(', ');
    }

    // 3) Mongoose CastError: a value can't be converted to the right type,
    //    e.g. User.findById('abc') where 'abc' is not a valid ObjectId.
    if (err.name === 'CastError') {
        statusCode = 400;
        message = `Invalid ${err.path}: ${err.value}`;
    }

    // 4) JWT errors (for when you add tokens). We only compare names, so no import is needed.
    if (err.name === 'JsonWebTokenError') {
        statusCode = 401; // 401 = Unauthorized
        message = 'Invalid token';
    }
    if (err.name === 'TokenExpiredError') {
        statusCode = 401;
        message = 'Token has expired, please sign in again';
    }

    // 5) Broken JSON in the request body, caught by express.json() before it reaches your routes.
    if (err.type === 'entity.parse.failed') {
        statusCode = 400;
        message = 'Invalid JSON in request body';
    }

    // ---------- Logging ----------

    // Log only server-side failures (5xx). Client mistakes (4xx) are normal and would just clutter the terminal.
    // We log the real error here, because the client will only see a safe message.
    if (statusCode >= 500) {
        console.error(err);
    }

    // ---------- Response ----------

    // res.status(...) sets the HTTP status code, .json(...) sends the body as JSON.
    // The spread `...(condition && { stack: err.stack })` adds the stack trace ONLY in development.
    // In production we never expose stack traces, because they leak details about your code.
    res.status(statusCode).json({
        success: false,
        message,
        ...(NODE_ENV === 'development' && { stack: err.stack }),
    });
};

// Export it so app.js can import it.
// Remember: in app.js, register it AFTER all your routes with app.use(errorMiddleware).
export default errorMiddleware;