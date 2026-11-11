const nodemailer = require("nodemailer");
const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = require("./settings");

const mailReady = Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS);
const port = Number(SMTP_PORT);
const transporter = mailReady ? nodemailer.createTransport({
  host: SMTP_HOST,
  port,
  secure: port === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
}) : null;

module.exports = { mailReady, transporter };