'use strict';
const nodemailer = require('nodemailer');

/**
 * @epheme/core - mailer
 *
 * Shared SMTP wrapper for all BafGo suite services.
 * Reads configuration from environment variables; gracefully no-ops if SMTP_HOST is unset.
 *
 * Environment variables:
 *   SMTP_HOST          - SMTP server hostname (required to send mail)
 *   SMTP_PORT          - port, default 587 (STARTTLS) or 465 (TLS)
 *   SMTP_SECURE        - "true" to use TLS on connect (port 465), else STARTTLS
 *   SMTP_USER          - SMTP username
 *   SMTP_PASS          - SMTP password
 *   SMTP_REJECT_UNAUTH - set "false" to accept self-signed certs (dev only)
 *   MAIL_FROM          - sender address; defaults to "BafGo <noreply@{host}>"
 */
const SMTP_HOST         = process.env.SMTP_HOST;
const SMTP_PORT         = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_SECURE       = process.env.SMTP_SECURE === 'true';
const SMTP_REJECT_UNAUTH= process.env.SMTP_REJECT_UNAUTH !== 'false';
const SMTP_USER         = process.env.SMTP_USER;
const SMTP_PASS         = process.env.SMTP_PASS;
const MAIL_FROM         = process.env.MAIL_FROM || `"BafGo" <noreply@${SMTP_HOST || 'localhost'}>`;

let _transport = null;

function _getTransport() {
  if (_transport) return _transport;
  if (!SMTP_HOST) throw new Error('SMTP_HOST is not configured - email sending is disabled.');
  _transport = nodemailer.createTransport({
    host:   SMTP_HOST,
    port:   SMTP_PORT,
    secure: SMTP_SECURE,
    auth:   (SMTP_USER && SMTP_PASS) ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    tls:    { rejectUnauthorized: SMTP_REJECT_UNAUTH },
  });
  return _transport;
}

/** Returns true when SMTP_HOST is configured - use to guard email UI features. */
function isEmailEnabled() {
  return Boolean(SMTP_HOST);
}

/**
 * Send a single email.
 * @param {{ to: string, subject: string, text: string, html?: string }} opts
 * @returns {Promise<object>} nodemailer info
 */
async function sendMail({ to, subject, text, html }) {
  return _getTransport().sendMail({ from: MAIL_FROM, to, subject, text, html });
}

module.exports = { sendMail, isEmailEnabled };
