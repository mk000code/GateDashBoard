require("dotenv").config();
const express = require("express"), mongoose = require("mongoose"), bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"), helmet = require("helmet"), rateLimit = require("express-rate-limit");
const path = require("path"), crypto = require("crypto"), nodemailer = require("nodemailer");
const { MONGODB_URI, JWT_SECRET, PORT = 3000, SMTP_HOST, SMTP_PORT = 587, SMTP_USER, SMTP_PASS, SMTP_FROM, APP_URL = `http://localhost:${PORT}` } = process.env;
if (!MONGODB_URI || !JWT_SECRET) { console.error("Set MONGODB_URI and JWT_SECRET in .env"); process.exit(1); }
if (!/^mongodb(\+srv)?:\/\/.+/i.test(MONGODB_URI)) {
  console.error("MONGODB_URI must be a valid MongoDB connection string, e.g. mongodb+srv://user:pass@cluster.mongodb.net/database");
  process.exit(1);
}

const User = mongoose.model("User", new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 120 },
  passwordHash: { type: String, required: true },
  emailVerified: { type: Boolean, default: true },
  emailVerificationTokenHash: String,
  emailVerificationExpiresAt: Date,
  passwordResetTokenHash: String,
  passwordResetExpiresAt: Date
}, { timestamps: true }));

const Progress = mongoose.model("Progress", new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", unique: true, required: true },
  data: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true, minimize: false }));

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  ...helmet.contentSecurityPolicy.getDefaultDirectives(),
  "script-src": ["'self'", "'unsafe-inline'"], "script-src-attr": ["'unsafe-inline'"]
} } }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: "Too many attempts. Try again later." } });
const sign = u => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: "30d" });
const isStr = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max;
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: "Server error" }); });
const mailReady = Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS);
const mailer = mailReady ? nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: Number(SMTP_PORT) === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
}) : null;
const tokenHash = token => crypto.createHash("sha256").update(token).digest("hex");
const makeToken = () => crypto.randomBytes(32).toString("hex");
const appUrl = APP_URL.replace(/\/+$/, "");
async function sendLink(to, subject, label, link) {
  await mailer.sendMail({
    from: SMTP_FROM || SMTP_USER,
    to,
    subject,
    text: `${label}\n\n${link}\n\nIf you did not request this, you can ignore this email.`,
    html: `<p>${label}</p><p><a href="${link}">${label}</a></p><p>If you did not request this, you can ignore this email.</p>`
  });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  try { req.uid = jwt.verify(h.replace("Bearer ", ""), JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: "Please sign in again" }); }
}

app.post("/api/register", authLimit, wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!isStr(name, 60) || !isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid name and email" });
  if (!isStr(password, 100) || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (!mailReady) return res.status(503).json({ error: "Email delivery is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS." });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: "Email already registered" });
  const verificationToken = makeToken();
  const u = await User.create({
    name, email, passwordHash: await bcrypt.hash(password, 12), emailVerified: false,
    emailVerificationTokenHash: tokenHash(verificationToken),
    emailVerificationExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });
  try {
    await sendLink(u.email, "Verify your GATE Command Center email", "Verify your email address", `${appUrl}/?verify=${verificationToken}`);
  } catch (e) {
    console.error("Verification email delivery failed:", e.message);
    return res.status(503).json({ error: "Account created, but the verification email could not be sent. Please try resending it." });
  }
  res.json({ verificationRequired: true });
}));

app.post("/api/login", authLimit, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!isStr(email, 120) || !isStr(password, 100)) return res.status(400).json({ error: "Enter email and password" });
  const u = await User.findOne({ email: email.toLowerCase() });
  if (!u || !(await bcrypt.compare(password, u.passwordHash))) return res.status(401).json({ error: "Wrong email or password" });
  if (!u.emailVerified) return res.status(403).json({ error: "Verify your email before signing in. You can resend the verification link." });
  res.json({ token: sign(u), user: { name: u.name, email: u.email } });
}));

app.post("/api/verify-email", authLimit, wrap(async (req, res) => {
  const { token } = req.body || {};
  if (!isStr(token, 200)) return res.status(400).json({ error: "Invalid or expired verification link" });
  const u = await User.findOne({
    emailVerificationTokenHash: tokenHash(token),
    emailVerificationExpiresAt: { $gt: new Date() }
  });
  if (!u) return res.status(400).json({ error: "Invalid or expired verification link" });
  u.emailVerified = true;
  u.emailVerificationTokenHash = undefined;
  u.emailVerificationExpiresAt = undefined;
  await u.save();
  res.json({ ok: true });
}));

app.post("/api/resend-verification", authLimit, wrap(async (req, res) => {
  const { email } = req.body || {};
  if (!isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
  if (!mailReady) return res.status(503).json({ error: "Email delivery is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS." });
  const u = await User.findOne({ email: email.toLowerCase() });
  if (!u || u.emailVerified) return res.json({ ok: true });
  const verificationToken = makeToken();
  u.emailVerificationTokenHash = tokenHash(verificationToken);
  u.emailVerificationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await u.save();
  try {
    await sendLink(u.email, "Verify your GATE Command Center email", "Verify your email address", `${appUrl}/?verify=${verificationToken}`);
  } catch (e) {
    console.error("Verification email delivery failed:", e.message);
    return res.status(503).json({ error: "The verification email could not be sent. Please try again later." });
  }
  res.json({ ok: true });
}));

app.post("/api/forgot-password", authLimit, wrap(async (req, res) => {
  const { email } = req.body || {};
  if (!isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
  if (!mailReady) return res.status(503).json({ error: "Email delivery is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS." });
  const u = await User.findOne({ email: email.toLowerCase() });
  if (!u) return res.json({ ok: true });
  const resetToken = makeToken();
  u.passwordResetTokenHash = tokenHash(resetToken);
  u.passwordResetExpiresAt = new Date(Date.now() + 60 * 60 * 1000);
  await u.save();
  try {
    await sendLink(u.email, "Reset your GATE Command Center password", "Reset your password", `${appUrl}/?reset=${resetToken}`);
  } catch (e) {
    console.error("Password reset email delivery failed:", e.message);
    return res.status(503).json({ error: "The password reset email could not be sent. Please try again later." });
  }
  res.json({ ok: true });
}));

app.post("/api/reset-password", authLimit, wrap(async (req, res) => {
  const { token, password } = req.body || {};
  if (!isStr(token, 200) || !isStr(password, 100) || password.length < 8) return res.status(400).json({ error: "Use a valid reset link and a password of at least 8 characters" });
  const u = await User.findOne({
    passwordResetTokenHash: tokenHash(token),
    passwordResetExpiresAt: { $gt: new Date() }
  });
  if (!u) return res.status(400).json({ error: "Invalid or expired password reset link" });
  u.passwordHash = await bcrypt.hash(password, 12);
  u.passwordResetTokenHash = undefined;
  u.passwordResetExpiresAt = undefined;
  await u.save();
  res.json({ ok: true });
}));

app.get("/api/me", auth, wrap(async (req, res) => {
  const u = await User.findById(req.uid);
  if (!u) return res.status(401).json({ error: "Account not found" });
  res.json({ user: { name: u.name, email: u.email } });
}));

app.get("/api/progress", auth, wrap(async (req, res) => {
  const p = await Progress.findOne({ user: req.uid });
  res.json({ data: p ? p.data : null, updatedAt: p ? p.updatedAt : null });
}));

const KEYS = ["done", "rev", "conf", "fin", "secs", "tests", "tm", "exam", "ts"];
app.put("/api/progress", auth, wrap(async (req, res) => {
  const d = req.body && req.body.data;
  if (!d || typeof d !== "object" || Array.isArray(d)) return res.status(400).json({ error: "Invalid data" });
  const clean = {};
  for (const k of KEYS) if (k in d) clean[k] = d[k];
  await Progress.findOneAndUpdate({ user: req.uid }, { data: clean }, { upsert: true, new: true, setDefaultsOnInsert: true });
  res.json({ ok: true });
}));

mongoose.connect(MONGODB_URI).then(() => {
  app.listen(PORT, () => console.log("Running on http://localhost:" + PORT));
}).catch(e => { console.error("MongoDB connection failed:", e.message); process.exit(1); });
