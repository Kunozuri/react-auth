// src/utils/asyncHandler.js
//
// THE PROBLEM IT SOLVES
// Express 4 (the version in your stack trace) does NOT catch errors thrown inside an `async` function.
// If an `await` fails and you have no try/catch, the request just hangs and Node may print an
// "unhandled promise rejection". That is why every controller had its own try/catch + next(error).
//
// THE FIX
// asyncHandler takes your async controller and returns a NEW function that Express can call.
// It runs your controller, and if the promise rejects (something threw), it calls next(error),
// which sends the error to your error middleware. You write the try/catch once, here, for everything.
//
// HOW TO READ IT
//   asyncHandler(fn)         -> you give it your controller
//   (req, res, next) => ...  -> it gives back a normal Express middleware
//   Promise.resolve(...)     -> makes sure we always have a promise, even if fn isn't async
//   .catch(next)             -> same as .catch((err) => next(err))
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

export default asyncHandler;