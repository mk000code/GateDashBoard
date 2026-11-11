const express = require("express");
const Progress = require("../models/Progress");
const User = require("../models/User");
const auth = require("../middleware/auth");
const wrap = require("../middleware/asyncHandler");

const router = express.Router();
const KEYS = ["done", "rev", "conf", "fin", "secs", "tests", "tm", "exam", "ts"];

router.get("/me", auth, wrap(async (req, res) => {
  const user = await User.findById(req.uid);
  if (!user) return res.status(401).json({ error: "Account not found" });
  res.json({ user: { name: user.name, email: user.email } });
}));

router.get("/progress", auth, wrap(async (req, res) => {
  const progress = await Progress.findOne({ user: req.uid });
  res.json({ data: progress ? progress.data : null, updatedAt: progress ? progress.updatedAt : null });
}));

router.put("/progress", auth, wrap(async (req, res) => {
  const data = req.body && req.body.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) return res.status(400).json({ error: "Invalid data" });
  const clean = {};
  for (const key of KEYS) if (key in data) clean[key] = data[key];
  await Progress.findOneAndUpdate({ user: req.uid }, { data: clean }, { upsert: true, new: true, setDefaultsOnInsert: true });
  res.json({ ok: true });
}));

module.exports = router;
