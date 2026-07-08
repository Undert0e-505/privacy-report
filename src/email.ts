import { createTransport } from 'nodemailer';
import type { Transporter } from 'nodemailer';

export interface EmailConfig {
  smtpHost: string;
  smtpPort: number;
  smtpUser: string;
  smtpPass: string;
  from: string;
}

/**
 * Send a report email to the configured contact.
 * Reads SMTP creds from env vars:
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 */
export async function sendReportEmail(
  to: string,
  cc: string | undefined,
  subject: string,
  body: string,
): Promise<boolean> {
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM;

  if (!host || !port || !user || !pass || !from) {
    console.log('[Email] SMTP not configured — skipping email send.');
    console.log('[Email] Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM env vars to enable.');
    return false;
  }

  // Don't send to placeholder addresses
  if (to.startsWith('REPLACE_') || to.includes('placeholder')) {
    console.log(`[Email] Contact email is a placeholder (${to}) — skipping send.`);
    return false;
  }

  const transporter: Transporter = createTransport({
    host,
    port: parseInt(port, 10),
    secure: parseInt(port, 10) === 465,
    auth: { user, pass },
  });

  const mailOptions: { from: string; to: string; cc?: string; subject: string; text: string } = {
    from,
    to,
    subject,
    text: body,
  };

  // Add CC if provided and not a placeholder
  if (cc && !cc.startsWith('REPLACE_') && !cc.includes('placeholder')) {
    mailOptions.cc = cc;
  }

  try {
    await transporter.sendMail(mailOptions);
    const ccInfo = mailOptions.cc ? ` (cc: ${mailOptions.cc})` : '';
    console.log(`[Email] Report sent to ${to}${ccInfo}`);
    return true;
  } catch (err) {
    console.error(`[Email] Failed to send: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  } finally {
    transporter.close();
  }
}