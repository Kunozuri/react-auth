// bcryptjs: a library that turns a plain password into a one-way "hash".
// We never store the real password, only the hash, so a database leak doesn't expose passwords.
import bcrypt from 'bcryptjs';

// jsonwebtoken: creates and verifies JWTs (the "token" the client sends back on later requests).
import jwt from 'jsonwebtoken';

// Our User model. In ES modules the ".js" at the end is REQUIRED, otherwise Node can't find the file.
import User from '../models/User.js';

// Secret key and expiry for tokens, read from your .env file through env.js.
import { JWT_SECRET, JWT_EXPIRES_IN } from '../config/env.js';

// A named constant instead of a "magic number" scattered in the code. Easy to change in one place.
const MIN_PASSWORD_LENGTH = 8;

// `async` because we use `await` inside (database + hashing are slow operations).
// (req, res, next) is the standard middleware shape, a controller is just the last middleware in the chain.
export const signUp = async (req, res, next) => {
    // Everything is inside try/catch so that ANY failed `await` jumps to the catch block at the bottom.
    // There we call next(error), which hands the error to your error middleware.
    try {
        // Destructuring: pull these three values out of the JSON body the client sent.
        // We deliberately take ONLY name, email and password. If we spread req.body into User.create(),
        // a user could send { "role": "admin" } and make themselves an admin.
        const { name, email, password } = req.body;

        // typeof check: makes sure email and password are plain strings.
        // Without it, someone could send an object like { "$gt": "" } as the email and trick the database query below
        // (this attack is called NoSQL injection).
        if (typeof email !== 'string' || typeof password !== 'string') {
            const error = new Error('Email and password are required');
            error.statusCode = 400; // 400 = Bad Request (the client sent bad data)
            throw error;            // throw jumps straight to the catch block below
        }

        // Check the password length HERE, before hashing.
        // The model also has minlength: 8, but that rule only sees the final value being saved.
        // A bcrypt hash is always 60 characters, so after hashing the model's check would always pass,
        // even for a 1-character password.
        if (password.length < MIN_PASSWORD_LENGTH) {
            const error = new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
            error.statusCode = 400;
            throw error;
        }

        // Normalize the email: trim() removes spaces at the ends, toLowerCase() makes "A@B.com" and "a@b.com" the same.
        // The model does this too, but doing it here makes sure our own search below uses the same value.
        const normalizedEmail = email.trim().toLowerCase();

        // Look for an existing user with this email. `await` pauses until the database answers.
        // findOne returns the user document, or null if nobody has this email.
        const existingUser = await User.findOne({ email: normalizedEmail });

        // If we found someone, the email is taken.
        if (existingUser) {
            const error = new Error('Email already in use');
            error.statusCode = 409; // 409 = Conflict
            throw error;
        }

        // A "salt" is random data mixed into the password before hashing, so two users with the same
        // password get different hashes. The number 10 is the cost: higher = safer but slower. 10 is the usual default.
        const salt = await bcrypt.genSalt(10);

        // Turn the plain password into the hash we will store. This is slow on purpose (to make brute force harder),
        // which is why it needs `await`.
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create and save the user in one step. Mongoose runs the model's validation first
        // (the match, minlength and enum rules), and throws a ValidationError if something fails.
        // That error is caught below and your error middleware turns it into a 400 response.
        // `name` may be undefined, which is fine because the model doesn't require it.
        const newUser = await User.create({
            name,
            email: normalizedEmail,
            password: hashedPassword,
        });

        // Build a token that proves "this request comes from this user".
        // 1st argument: the payload (data stored inside the token). Keep it small, and never put passwords in it.
        // 2nd argument: your secret key, used to sign the token so nobody can forge one.
        // 3rd argument: options. expiresIn makes the token stop working after a while (e.g. '1d').
        const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, {
            expiresIn: JWT_EXPIRES_IN,
        });

        // `select: false` in the model only hides the password when you QUERY (find, findOne...).
        // The document returned by create() still contains it, so we remove it before sending the response.
        // toObject() converts the Mongoose document into a plain JavaScript object we can edit.
        const userData = newUser.toObject();
        delete userData.password;

        // 201 = Created (the correct status for "a new resource was made").
        // The client gets the token and the user's info (without the password).
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: {
                token,
                user: userData,
            },
        });
    } catch (error) {
        // Any error thrown above (ours, Mongoose's, bcrypt's...) ends up here.
        // next(error) sends it to the error middleware, which decides the status code and message.
        next(error);
    }
};

// ---------------------------------------------------------------------------
// SIGN IN
// ---------------------------------------------------------------------------
export const signIn = async (req, res, next) => {
    try {
        // req.body holds the data the client SENT (the JSON with email and password).
        // `res` is the opposite: it's what we use to SEND the answer back. So we read from req, reply with res.
        const { email, password } = req.body;

        // Same type check as sign-up: make sure both are plain strings (protects the database query below).
        if (typeof email !== 'string' || typeof password !== 'string') {
            const error = new Error('Email and password are required');
            error.statusCode = 400;
            throw error;
        }

        // Normalize the email the same way we did when the user signed up, otherwise "A@B.com" wouldn't match "a@b.com".
        const normalizedEmail = email.trim().toLowerCase();

        // Find the user by email. Two details here:
        // - deletedAt: null  -> only match accounts that haven't been soft-deleted.
        // - .select('+password') -> the model hides the password by default (select: false).
        //   The "+" means "include it this time", because we need the hash to compare.
        const user = await User.findOne({ email: normalizedEmail, deletedAt: null }).select('+password');

        // No user with that email. We use the SAME message as the wrong-password case below,
        // so an attacker can't use this form to discover which emails are registered.
        if (!user) {
            const error = new Error('Invalid credentials');
            error.statusCode = 401; // 401 = Unauthorized
            throw error;
        }

        // The database stores a hash, not the real password, so we can't compare with ===.
        // bcrypt.compare hashes the typed password the same way and tells us if they match (true/false).
        // It returns a Promise, so it needs `await`.
        const isPasswordValid = await bcrypt.compare(password, user.password);

        // Wrong password: same message as above on purpose.
        if (!isPasswordValid) {
            const error = new Error('Invalid credentials');
            error.statusCode = 401;
            throw error;
        }

        // We check the account status AFTER the password, so only someone who knows the password
        // learns that the account is suspended. 403 = Forbidden (we know who you are, but you're not allowed in).
        if (user.status === 'suspended') {
            const error = new Error('This account has been suspended');
            error.statusCode = 403;
            throw error;
        }

        // Record when the user last signed in. updateOne changes just that one field in the database,
        // without loading and re-saving the whole document.
        await User.updateOne({ _id: user._id }, { lastLoginAt: new Date() });

        // Create the token, exactly like in sign-up: payload, secret, expiry.
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
            expiresIn: JWT_EXPIRES_IN,
        });

        // The user document still carries the password hash (we asked for it with +password),
        // so convert it to a plain object and delete the password before sending anything to the client.
        const userData = user.toObject();
        delete userData.password;

        // 200 = OK. (Sign-up used 201 because it created something; sign-in creates nothing, it just succeeds.)
        res.status(200).json({
            success: true,
            message: 'User signed in successfully',
            data: {
                token,
                user: userData,
            },
        });
    } catch (error) {
        // Send any error to the error middleware, same as in signUp.
        next(error);
    }
};


export const signOut = async (req, res, next) => {

}


/*export const getMe = (req, res) => {
    // req.user was attached by authMiddleware, so we can just send it back
    res.json({ success: true, data: { user: req.user } });
};*/