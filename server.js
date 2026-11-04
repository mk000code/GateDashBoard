require("dotenv").config();
const express = require("express"), mongoose = require("mongoose"), bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"), helmet = require("helmet"), rateLimit = require("express-rate-limit");
const path = require("path");
const { MONGODB_URI, JWT_SECRET, PORT = 3000 } = process.env;
if (!MONGODB_URI || !JWT_SECRET) { console.error("Set MONGODB_URI and JWT_SECRET in .env"); process.exit(1); }
if (!/^mongodb(\+srv)?:\/\/.+/i.test(MONGODB_URI)) {
  console.error("MONGODB_URI must be a valid MongoDB connection string, e.g. mongodb+srv://user:pass@cluster.mongodb.net/database");
  process.exit(1);
}

const User = mongoose.model("User", new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 120 },
  passwordHash: { type: String, required: true }
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

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  try { req.uid = jwt.verify(h.replace("Bearer ", ""), JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: "Please sign in again" }); }
}

app.post("/api/register", authLimit, wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!isStr(name, 60) || !isStr(email, 120) || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid name and email" });
  if (!isStr(password, 100) || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: "Email already registered" });
  const u = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12) });
  res.json({ token: sign(u), user: { name: u.name, email: u.email } });
}));

app.post("/api/login", authLimit, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!isStr(email, 120) || !isStr(password, 100)) return res.status(400).json({ error: "Enter email and password" });
  const u = await User.findOne({ email: email.toLowerCase() });
  if (!u || !(await bcrypt.compare(password, u.passwordHash))) return res.status(401).json({ error: "Wrong email or password" });
  res.json({ token: sign(u), user: { name: u.name, email: u.email } });
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
