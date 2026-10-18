import mongoose from 'mongoose';

// ---------- Validation patterns ----------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const URL_REGEX = /^https?:\/\/[^\s/$.?#][^\s]*$/i;

const ROLES = ['user', 'admin', 'moderator'];
const STATUSES = ['active', 'suspended', 'pending'];

const userSchema = new mongoose.Schema(
    {
        // ---------- Credentials ----------
        email: {
            type: String,
            required: [true, 'Email is required'],
            unique: true,
            lowercase: true,
            trim: true,
            maxlength: [254, 'Email is too long'],
            match: [EMAIL_REGEX, 'Please provide a valid email address'],
        },
        password: {
            type: String,
            required: [true, 'Password is required'],
            minlength: [8, 'Password must be at least 8 characters'],
            select: false, // never returned in queries unless you use .select('+password')
        },

        // ---------- Access control ----------
        role: {
            type: String,
            enum: { values: ROLES, message: '{VALUE} is not a valid role' },
            default: 'user',
        },
        status: {
            type: String,
            enum: { values: STATUSES, message: '{VALUE} is not a valid status' },
            default: 'active',
        },

        // ---------- Profile ----------
        name: {
            type: String,
            trim: true,
            minlength: [2, 'Name must be at least 2 characters'],
            maxlength: [50, 'Name must be at most 50 characters'],
        },
        avatar: {
            type: String,
            trim: true,
            match: [URL_REGEX, 'Avatar must be a valid http(s) URL'],
        },

        // ---------- Verification ----------
        isEmailVerified: { type: Boolean, default: false },
        emailVerificationToken: { type: String, select: false },
        emailVerificationExpires: { type: Date, select: false },

        // ---------- Security ----------
        lastLoginAt: Date,
        passwordChangedAt: Date,
        failedLoginAttempts: { type: Number, default: 0 },
        lockUntil: Date,
        passwordResetToken: { type: String, select: false },
        passwordResetExpires: { type: Date, select: false },

        // ---------- Soft delete ----------
        deletedAt: { type: Date, default: null },
    },
    { timestamps: true } // adds createdAt and updatedAt automatically
);

const User = mongoose.model('User', userSchema);

export default User;