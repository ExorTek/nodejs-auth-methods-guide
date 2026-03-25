import nodemailer from 'nodemailer';
import { generateToken, logger } from '@auth-guide/shared';

/**
 * Magic Link email utility
 *
 * Generates a cryptographically random token, stores hash in DB,
 * sends plaintext token as a clickable link via email.
 */

let transporter = null;

const getTransporter = () => {
  if (transporter) return transporter;

  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.ethereal.email',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  return transporter;
};

/**
 * Generate a magic link token
 * @returns {string} Random 64-char hex token
 */
const generateMagicToken = () => generateToken(32);

/**
 * Send magic link email
 *
 * @param {string} to - Recipient email
 * @param {string} magicUrl - Full magic link URL
 */
const sendMagicLinkEmail = async (to, magicUrl) => {
  const transport = getTransporter();

  const info = await transport.sendMail({
    from: process.env.EMAIL_FROM || 'noreply@authguide.dev',
    to,
    subject: 'Your sign-in link',
    text: `Click this link to sign in:\n\n${magicUrl}\n\nThis link expires in 10 minutes.\nIf you did not request this, please ignore this email.`,
    html: `
      <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">Sign In</h2>
        <p style="color: #666;">Click the button below to sign in to your account:</p>
        <a href="${magicUrl}" style="display: inline-block; background: #2563eb; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin: 16px 0; font-size: 16px;">Sign In</a>
        <p style="color: #999; font-size: 14px;">This link expires in 10 minutes.</p>
        <p style="color: #999; font-size: 14px;">If you did not request this, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #bbb; font-size: 12px;">Or copy this URL: ${magicUrl}</p>
      </div>
    `,
  });

  if (process.env.SMTP_HOST?.includes('ethereal')) {
    const previewUrl = nodemailer.getTestMessageUrl(info);
    logger.info({ msg: 'Magic link sent (Ethereal preview)', to, previewUrl });
  } else {
    logger.info({ msg: 'Magic link sent', to, messageId: info.messageId });
  }

  return info;
};

export { generateMagicToken, sendMagicLinkEmail };
