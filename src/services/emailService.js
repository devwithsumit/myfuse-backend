import nodemailer from 'nodemailer';

export const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 587,
  secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',

  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Verify the SMTP connection
(async () => {
  try {
    const result = await transporter.verify();
    console.log('Email service ready ✅');
  } catch (e) {
    console.error('SMTP verify failed:', e.message);
  }
})();

export async function sendOtpEmail(to, name, otp) {
  const appName = process.env.APP_NAME || 'MyFuse';
  const fromEmail = process.env.APP_FROM_EMAIL || process.env.SMTP_USER;
  const html = otpEmailTemplate({ name, otp, appName });
  const subject = `${appName} Verification Code: ${otp}`;

  // Send the email
  try {
    await transporter.sendMail({
      from: `${appName} <${fromEmail}>`,
      to,
      subject,
      html,
    });
  } catch (e) {
    console.error('Email send failed:', e.message);
  }
}

function otpEmailTemplate({ name, otp, appName }) {
  const safeName = name || 'there';
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${appName} Verification Code</title>
    <style>
      body { background: #f6f8fb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, 'Helvetica Neue', Arial, sans-serif; color: #1f2937; margin: 0; padding: 0; }
      .container { max-width: 520px; margin: 24px auto; padding: 0 16px; }
      .card { background: #ffffff; border-radius: 12px; box-shadow: 0 10px 20px rgba(0,0,0,0.06); padding: 28px; }
      .brand { font-weight: 700; font-size: 18px; color: #111827; }
      .greeting { margin: 12px 0 6px; font-size: 16px; }
      .lead { margin: 0 0 18px; color: #4b5563; }
      .otp { display: inline-block; letter-spacing: 6px; font-size: 28px; font-weight: 700; color: #111827; background: #f3f4f6; padding: 12px 16px; border-radius: 10px; border: 1px solid #e5e7eb; }
      .meta { margin-top: 14px; color: #6b7280; font-size: 14px; }
      .footer { margin-top: 24px; color: #9ca3af; font-size: 12px; text-align: center; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="card">
        <div class="brand">${appName}</div>
        <p class="greeting">Hi ${safeName},</p>
        <p class="lead">Use the following verification code to complete your sign up:</p>
        <div>
          <span class="otp">${otp}</span>
        </div>
        <p class="meta">This code expires in 5 minutes. If you didn’t request this, you can safely ignore this email.</p>
      </div>
      <div class="footer">&copy; ${new Date().getFullYear()} ${appName}. All rights reserved.</div>
    </div>
  </body>
  </html>`;
}


