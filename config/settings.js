
const path = require("path");

// Load .env from the project root
require("dotenv").config({
    path: path.join(__dirname, "..", ".env")
});

const {
    MONGODB_URI,
    JWT_SECRET,
    PORT = 3001,
    SMTP_HOST,
    SMTP_PORT = 587,
    SMTP_USER,
    SMTP_PASS,
    SMTP_FROM,
    APP_URL = `http://localhost:${PORT}`
} = process.env;

// Validate required variables
if (!MONGODB_URI || !JWT_SECRET) {
    console.error("Set MONGODB_URI and JWT_SECRET in .env");
    process.exit(1);
}

// Validate MongoDB connection string
if (!/^mongodb(\+srv)?:\/\//i.test(MONGODB_URI)) {
    console.error("Invalid MongoDB connection string");
    process.exit(1);
}

module.exports = {
    MONGODB_URI,
    JWT_SECRET,
    PORT,
    SMTP_HOST,
    SMTP_PORT: Number(SMTP_PORT),
    SMTP_USER,
    SMTP_PASS,
    SMTP_FROM,
    APP_URL
};
