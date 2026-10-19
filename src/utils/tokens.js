// src/utils/tokens.js
import jwt from 'jsonwebtoken';
import crypto from 'crypto'; // built into Node, nothing to install
import RefreshToken from '../models/RefreshToken.js';
import { JWT_SECRET } from '../config/env.js';

// Keep the lifetimes in one place so they are easy to change.
// To test expiry, temporarily change '15m' to '15s'.
const ACCESS_TOKEN_EXPIRES = '15m';
const REFRESH_DAYS = 7;
const REFRESH_MS = REFRESH_DAYS * 24 * 60 * 60 * 1000; // days -> milliseconds

// Turns a token into a fixed-length hash. The same input always gives the
// same output, so we can look the token up later without storing it.
// SHA-256 is fine here because the token is long and random. Passwords need
// bcrypt because people choose weak ones, but random tokens can't be guessed.
export const hashToken = (token) =>
    crypto.createHash('sha256').update(token).digest('hex');

// ACCESS TOKEN: a short-lived JWT, sent in the Authorization header.
// The server does NOT store it. It only verifies the signature and expiry.
export const signAccessToken = (user) =>
    jwt.sign(
        { userId: user._id, role: user.role }, // was `id`, now matches decoded.userId
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRES }
    );

// REFRESH TOKEN: a long random string (not a JWT), valid for 7 days.
// Unlike the access token, this one IS stored in the database, which is what
// lets us revoke it on sign-out.
export const createRefreshToken = async (userId) => {
    // 40 random bytes -> an 80-character hex string. Practically impossible to guess.
    const token = crypto.randomBytes(40).toString('hex');

    // Save only the hash in the database
    await RefreshToken.create({
        user: userId,
        tokenHash: hashToken(token),
        expiresAt: new Date(Date.now() + REFRESH_MS),
    });

    // Return the real token so the controller can put it in the cookie
    return token;
};

// Options for the cookie that holds the refresh token
export const refreshCookieOptions = {
    httpOnly: true, // JavaScript in the browser can't read it, so XSS can't steal it
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production (localhost uses http)
    sameSite: 'lax', // not sent on cross-site requests, which helps against CSRF
    maxAge: REFRESH_MS, // how long the browser keeps the cookie
};

// clearCookie must use the same options as when the cookie was set,
// but without maxAge, or the browser may not remove it.
// This line copies refreshCookieOptions except for maxAge.
const { maxAge, ...clearCookieOptions } = refreshCookieOptions;
export { clearCookieOptions };