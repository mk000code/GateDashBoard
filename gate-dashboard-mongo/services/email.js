const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { APP_URL, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = require("../config/settings");
const transporter = require("../config/mailer");

transporter.verify(error => {
  if (error) {
    console.log("SMTP Error:", error);
  } else {
    console.log("SMTP Server is ready!");
  }
});

const mailReady = Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS);
const mailer = mailReady ? nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: Number(SMTP_PORT) === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
}) : null;
const appUrl = APP_URL.replace(/\/+$/, "");

const tokenHash = token => crypto.createHash("sha256").update(token).digest("hex");
const makeToken = () => crypto.randomBytes(32).toString("hex");

async function sendLink(to, subject, label, link) {
  await mailer.sendMail({
    from: SMTP_FROM || SMTP_USER,
    to,
    subject,
    text: `${label}\n\n${link}\n\nIf you did not request this, you can ignore this email.`,
    html: `<p>${label}</p><p><a href="${link}">${label}</a></p><p>If you did not request this, you can ignore this email.</p>`
  });
}

module.exports = { mailReady, tokenHash, makeToken, sendLink, appUrl };
