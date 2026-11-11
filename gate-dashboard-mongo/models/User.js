const mongoose = require("mongoose");

module.exports = mongoose.model("User", new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 120 },
  passwordHash: { type: String, required: true },
  emailVerified: { type: Boolean, default: true },
  emailVerificationTokenHash: String,
  emailVerificationExpiresAt: Date,
  passwordResetTokenHash: String,
  passwordResetExpiresAt: Date,
  passwordResetTokens: [{ tokenHash: String, expiresAt: Date }]
}, { timestamps: true }));
