const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/settings");

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  try {
    req.uid = jwt.verify(header.replace("Bearer ", ""), JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: "Please sign in again" });
  }
}

module.exports = auth;
