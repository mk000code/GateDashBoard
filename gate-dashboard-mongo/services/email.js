const crypto = require("crypto");
const { APP_URL, SMTP_USER, SMTP_FROM } = require("../config/settings");
const { mailReady, transporter } = require("../config/mailer");

if (transporter) {
  transporter.verify(error => {
    if (error) {
      console.error("SMTP verification failed:", error.message);
    } else {
      console.log("SMTP server is ready for email.");
    }
  });
}
const appUrl = APP_URL.replace(/\/+$/, "");

const tokenHash = token => crypto.createHash("sha256").update(token).digest("hex");
const makeToken = () => crypto.randomBytes(32).toString("hex");

async function sendLink(to, subject, label, link) {
  if (!transporter) throw new Error("Email delivery is not configured");
  await transporter.sendMail({
    from: SMTP_FROM || SMTP_USER,
    to,
    subject,
    text: `${label}\n\n${link}\n\nIf you did not request this, you can ignore this email.`,
    html: `<p>${label}</p><p><a href="${link}">${label}</a></p><p>If you did not request this, you can ignore this email.</p>`
  });
}

module.exports = { mailReady, tokenHash, makeToken, sendLink, appUrl };
