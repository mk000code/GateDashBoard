# GATE CS/IT Command Center (MongoDB + Login)

Node/Express API + MongoDB (Mongoose). Passwords are hashed with bcrypt, sessions use JWT, and each user's progress is stored under their own account.

The server is split into `routes/`, `models/`, `middleware/`, and `services/`; `app.js` assembles the Express application and `server.js` starts it.

## Run locally
1. Install Node 18+.
2. Create a MongoDB Atlas cluster and copy its connection string.
3. If you do not already have a `.env`, copy `.env.example` to `.env`. Otherwise keep its existing database and secret values, and add the SMTP settings described below.
4. Run `npm install` and `npm start`, then open http://localhost:3000.

## Deploy (Render or another host)
1. Push this folder to a GitHub repository and create a web service.
2. Use `npm install` for the build command and `npm start` for the start command.
3. Set `MONGODB_URI`, `JWT_SECRET`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `APP_URL` in the hosting provider's environment settings. Set `APP_URL` to the public site URL.

## Email verification and password reset
Email delivery uses SMTP. Configure `SMTP_HOST`, `SMTP_PORT` (587 by default; 465 uses TLS), `SMTP_USER`, `SMTP_PASS`, and optionally `SMTP_FROM`. The `.env.example` file shows the expected format. For Gmail, enable 2-Step Verification and create an App Password; use that app password for `SMTP_PASS`, not your normal Google password.

After updating local `.env`, restart the server. For deployment, configure the same values in the host's environment settings rather than uploading `.env`. If the UI says email delivery is not configured, check that `SMTP_HOST`, `SMTP_USER`, and `SMTP_PASS` are set in the environment where the Node server is running. New accounts must verify their email before signing in. Verification links expire after 24 hours; password-reset links expire after 1 hour.

## API
`POST /api/register`, `POST /api/login`, `POST /api/verify-email`, `POST /api/resend-verification`, `POST /api/forgot-password`, `POST /api/reset-password`, `GET /api/me`, and `GET/PUT /api/progress`.

## Backups
Use Atlas backups, or schedule `mongodump`, to keep data safe.
