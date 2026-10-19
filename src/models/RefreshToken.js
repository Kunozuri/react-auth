// src/models/RefreshToken.js
import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema(
    {
        // Which user this refresh token belongs to
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

        // We store a HASH of the token, never the token itself.
        // If someone steals your database, they get hashes they can't use,
        // the same idea as storing hashed passwords.
        tokenHash: { type: String, required: true, unique: true },

        // When this token stops being valid
        expiresAt: { type: Date, required: true },
    },
    { timestamps: true } // Mongoose adds createdAt and updatedAt automatically
);

// TTL index: MongoDB deletes a document automatically once the time in
// expiresAt has passed (expireAfterSeconds: 0 means "right at that time").
// This keeps the collection clean without any cleanup code.
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model('RefreshToken', refreshTokenSchema);