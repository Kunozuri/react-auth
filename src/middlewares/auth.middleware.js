// jsonwebtoken: we use it here to VERIFY tokens (in the controller we used it to create them).
import jwt from 'jsonwebtoken';

// The User model, so we can load the person the token belongs to.
import User from '../models/User.js';

// The same secret that was used to sign the token in sign-up and sign-in.
// verify() uses it to check the token wasn't forged or edited.
import { JWT_SECRET } from '../config/env.js';

// A normal middleware has THREE parameters: (req, res, next).
// It's `async` because we use `await` for the database lookup.
const authMiddleware = async (req, res, next) => {
    // try/catch so any failure (bad token, database error...) goes to the error middleware with next(error).
    try {
        // The client sends the token in a header that looks like:  Authorization: Bearer eyJhbGciOi...
        // Node lowercases all header names, so we read it as `authorization`.
        const authHeader = req.headers.authorization;

        // No header, or it doesn't start with "Bearer " -> the client didn't send a token at all.
        // The `!authHeader ||` part comes first on purpose: if the header is missing,
        // we stop there and never call .startsWith() on undefined (which would crash).
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            const error = new Error('Not authorized, no token provided');
            error.statusCode = 401; // 401 = Unauthorized
            throw error;            // jumps to the catch block below
        }

        // The header is "Bearer <token>". split(' ') cuts it at the space into ['Bearer', '<token>'],
        // and [1] picks the second piece, the token itself.
        const token = authHeader.split(' ')[1];

        // Check the token. If the signature is wrong or it has expired, verify() THROWS an error
        // (JsonWebTokenError or TokenExpiredError). We don't catch it here, the catch block below does,
        // and your error middleware already turns those two errors into a 401 response.
        // If it's valid, `decoded` is the payload we put inside it: { userId: '...', iat: ..., exp: ... }.
        // (iat = issued at, exp = expires at, both in seconds. JWT adds them automatically.)
        const decoded = jwt.verify(token, JWT_SECRET);

        // A valid token isn't enough: the user could have been deleted after the token was issued.
        // So we look them up in the database. deletedAt: null skips soft-deleted accounts.
        // The password is NOT included, because the model hides it by default (select: false).
        const user = await User.findOne({ _id: decoded.userId, deletedAt: null });

        // Token is valid, but the user no longer exists.
        if (!user) {
            const error = new Error('Not authorized, user no longer exists');
            error.statusCode = 401;
            throw error;
        }

        // A suspended account shouldn't keep working just because its old token hasn't expired yet.
        // 403 = Forbidden (we know who you are, but you're not allowed in).
        if (user.status === 'suspended') {
            const error = new Error('This account has been suspended');
            error.statusCode = 403;
            throw error;
        }

        // If the user changed their password after this token was issued, the token is outdated and must be rejected.
        // passwordChangedAt is a Date, so getTime() gives milliseconds; we divide by 1000 to get seconds,
        // because decoded.iat is in seconds. Math.floor drops the decimals.
        // (Until you build "change password", passwordChangedAt is empty and this check is simply skipped.)
        if (user.passwordChangedAt) {
            const changedAt = Math.floor(user.passwordChangedAt.getTime() / 1000);
            if (decoded.iat < changedAt) {
                const error = new Error('Password was changed recently, please sign in again');
                error.statusCode = 401;
                throw error;
            }
        }

        // Attach the user to the request object. Every function that runs AFTER this one
        // (other middleware, the controller) can now read req.user to know who is calling.
        req.user = user;

        // Everything checked out: pass the request to the next function in the chain (usually the controller).
        // Forgetting this line would make the request hang forever.
        next();
    } catch (error) {
        // Any error thrown above ends up here. next(error) skips all normal middleware
        // and goes straight to your error middleware.
        next(error);
    }
};

// Export it so route files can import it and put it before a controller.
export default authMiddleware;