import { Router } from 'express';

import { signIn, signUp, signOut, getMe } from "../controllers/auth.controller.js";

import authMiddleware from '../middlewares/auth.middleware.js';

const userAuthRouter = Router();

userAuthRouter.post('/sign-in', signIn); // PATH : /api/auth/sign-in
userAuthRouter.post('/sign-up', signUp); // PATH : /api/auth/sign-up
userAuthRouter.post('/sign-out', signOut); // PATH : /api/auth/sign-out

// tester
userAuthRouter.get('/me', authMiddleware, getMe);   // authMiddleware runs first, then getMe

export default userAuthRouter;