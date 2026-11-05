const mongoose = require("mongoose");

module.exports = mongoose.model("Progress", new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", unique: true, required: true },
  data: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true, minimize: false }));
