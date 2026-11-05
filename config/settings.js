require("dotenv").config();

const {
  MONGODB_URI,
  JWT_SECRET,
  PORT = 3000,
  SMTP_HOST,
  SMTP_PORT = 587,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  APP_URL = `http://localhost:${PORT}`
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error("Set MONGODB_URI and JWT_SECRET in .env");
  process.exit(1);
}

if (!/^mongodb(\+srv)?:\/\/.+/i.test(MONGODB_URI)) {
  console.error("MONGODB_URI must be a valid MongoDB connection string, e.g. ******cluster.mongodb.net/database");
  process.exit(1);
}

module.exports = {
  MONGODB_URI,
  JWT_SECRET,
  PORT,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  APP_URL
};
