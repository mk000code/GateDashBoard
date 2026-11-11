const express = require("express");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { sign } = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/settings");
const User = require("../models/User");
const wrap = require("../middleware/asyncHandler");
const { mailReady, tokenHash, makeToken, sendLink, appUrl } = require("../services/email");

const router = express.Router();
const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: "Too many attempts. Try again later." }
});
const signUser = user => sign({ id: user._id }, JWT_SECRET, { expiresIn: "30d" });
const isStr = (value, max) => typeof value === "string" && value.length > 0 && value.length <= max;

router.post("/register", authLimit, wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!isStr(name, 60) || !isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid name and email" });
  if (!isStr(password, 100) || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (!mailReady) return res.status(503).json({ error: "Email delivery is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS." });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: "Email already registered" });
  const verificationToken = makeToken();
  const user = await User.create({
    name, email, passwordHash: await bcrypt.hash(password, 12), emailVerified: false,
    emailVerificationTokenHash: tokenHash(verificationToken),
    emailVerificationExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });
  try {
    await sendLink(user.email, "Verify your GATE Command Center email", "Verify your email address", `${appUrl}/?verify=${verificationToken}`);
  } catch (error) {
    console.error("Verification email delivery failed:", error.message);
    return res.status(503).json({ error: "Account created, but the verification email could not be sent. Please try resending it." });
  }
  res.json({ verificationRequired: true });
}));

router.post("/login", authLimit, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!isStr(email, 120) || !isStr(password, 100)) return res.status(400).json({ error: "Enter email and password" });
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: "Wrong email or password" });
  if (!user.emailVerified) return res.status(403).json({ error: "Verify your email before signing in. You can resend the verification link." });
  res.json({ token: signUser(user), user: { name: user.name, email: user.email } });
}));

router.post("/verify-email", authLimit, wrap(async (req, res) => {
  const { token } = req.body || {};
  if (!isStr(token, 200)) return res.status(400).json({ error: "Invalid or expired verification link" });
  const user = await User.findOne({
    emailVerificationTokenHash: tokenHash(token),
    emailVerificationExpiresAt: { $gt: new Date() }
  });
  if (!user) return res.status(400).json({ error: "Invalid or expired verification link" });
  user.emailVerified = true;
  user.emailVerificationTokenHash = undefined;
  user.emailVerificationExpiresAt = undefined;
  await user.save();
  res.json({ ok: true });
}));

router.post("/resend-verification", authLimit, wrap(async (req, res) => {
  const { email } = req.body || {};
  if (!isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
  if (!mailReady) return res.status(503).json({ error: "Email delivery is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS." });
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || user.emailVerified) return res.json({ ok: true });
  const verificationToken = makeToken();
  user.emailVerificationTokenHash = tokenHash(verificationToken);
  user.emailVerificationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await user.save();
  try {
    await sendLink(user.email, "Verify your GATE Command Center email", "Verify your email address", `${appUrl}/?verify=${verificationToken}`);
  } catch (error) {
    console.error("Verification email delivery failed:", error.message);
    return res.status(503).json({ error: "The verification email could not be sent. Please try again later." });
  }
  res.json({ ok: true });
}));

router.post("/forgot-password", authLimit, wrap(async (req, res) => {
  const { email } = req.body || {};
  if (!isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
  if (!mailReady) return res.status(503).json({ error: "Email delivery is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS." });
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.json({ ok: true });
  const resetToken = makeToken();
  const now = new Date();
  const resetTokens = (user.passwordResetTokens || [])
    .filter(token => token.expiresAt > now);
  if (user.passwordResetTokenHash && user.passwordResetExpiresAt > now) {
    resetTokens.push({
      tokenHash: user.passwordResetTokenHash,
      expiresAt: user.passwordResetExpiresAt
    });
  }
  resetTokens.push({
    tokenHash: tokenHash(resetToken),
    expiresAt: new Date(now.getTime() + 60 * 60 * 1000)
  });
  user.passwordResetTokens = resetTokens.slice(-5);
  user.passwordResetTokenHash = undefined;
  user.passwordResetExpiresAt = undefined;
  await user.save();
  try {
    await sendLink(user.email, "Reset your GATE Command Center password", "Reset your password", `${appUrl}/?reset=${resetToken}`);
  } catch (error) {
    console.error("Password reset email delivery failed:", error.message);
    return res.status(503).json({ error: "The password reset email could not be sent. Please try again later." });
  }
  res.json({ ok: true });
}));

router.post("/reset-password", authLimit, wrap(async (req, res) => {
  const { token, password } = req.body || {};
  if (!isStr(token, 200) || !isStr(password, 100) || password.length < 8) return res.status(400).json({ error: "Use a valid reset link and a password of at least 8 characters" });
  const now = new Date();
  const hashedToken = tokenHash(token);
  const user = await User.findOne({
    $or: [
      {
        passwordResetTokenHash: hashedToken,
        passwordResetExpiresAt: { $gt: now }
      },
      {
        passwordResetTokens: {
          $elemMatch: {
            tokenHash: hashedToken,
            expiresAt: { $gt: now }
          }
        }
      }
    ]
  });
  if (!user) return res.status(400).json({ error: "Invalid or expired password reset link" });
  user.passwordHash = await bcrypt.hash(password, 12);
  user.passwordResetTokenHash = undefined;
  user.passwordResetExpiresAt = undefined;
  user.passwordResetTokens = [];
  await user.save();
  res.json({ ok: true });
}));

module.exports = router;
