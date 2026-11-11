
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const path = require("path");

const authRoutes = require("./routes/auth");
const progressRoutes = require("./routes/progress");

const app = express();

app.set("trust proxy", 1);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'"],
            "script-src-attr": ["'unsafe-inline'"]
        }
    }
}));

app.use(express.json({ limit: "1mb" }));

app.use(express.static(path.join(__dirname, "public")));

app.use("/api", authRoutes);
app.use("/api", progressRoutes);

module.exports = app;
