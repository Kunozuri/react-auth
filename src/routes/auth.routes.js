// src/routes/auth.routes.js
import { Router } from 'express';

// NEW: add `refresh` to this import. `signOut` was already exported
// from the controller, but it was empty before, so check it's imported too.
import { signUp, signIn, signOut, refresh, getMe } from '../controllers/auth.controller.js';

// ...keep your other imports here (authMiddleware, rate limiter, validators...)
import authMiddleware from '../middlewares/auth.middleware.js';

const router = Router();

// ...keep your existing routes, for example:
router.post('/sign-up', signUp);
router.post('/sign-in', signIn);

// NEW: asks for a new access token using the refresh cookie.
// It has no authMiddleware, because the access token is already expired when this is called.
router.post('/refresh', refresh);

// Make sure sign-out points to the real signOut controller.
// It needs no authMiddleware either, because it works from the cookie.
router.post('/sign-out', signOut);

router.get('/me', authMiddleware, getMe); // keep as you have it

export default router;