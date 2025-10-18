import nodemailer from 'nodemailer';

// Simple in-memory rate limiter (per function instance). Not perfect for global rate limiting.
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const MAX_PER_WINDOW = 6;
let requests = [];
function rateLimitOk(ip) {
  const now = Date.now();
  requests = requests.filter(r => now - r.ts < RATE_LIMIT_WINDOW_MS);
  const count = requests.filter(r => r.ip === ip).length;
  if (count >= MAX_PER_WINDOW) return false;
  requests.push({ ip, ts: now });
  return true;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!rateLimitOk(ip)) return res.status(429).json({ ok: false, error: 'Too many requests' });

  const { name = '', email = '', message = '', _gotcha = '' } = req.body || {};

  // Honeypot
  if (_gotcha) return res.status(200).json({ ok: true, spam: true });

  // Basic validation
  const clean = s => String(s).replace(/[<>]/g, '').trim();
  const cName = clean(name);
  const cEmail = clean(email);
  const cMessage = String(message).trim();

  if (!cName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cEmail) || !cMessage) {
    return res.status(400).json({ ok: false, error: 'Invalid input' });
  }

  console.log(process.env.SMTP_USER, process.env.SMTP_PASS);

  // Create transporter using GoDaddy Workspace SMTP
  const transporter = nodemailer.createTransport({
    host: 'smtpout.secureserver.net',
    port: 465,             // TLS
    secure: true,         // true for 465
    auth: {
      user: process.env.SMTP_USER, // hello@yourdomain.com
      pass: process.env.SMTP_PASS,
    },
    // Optional: increase timeout if you see timeouts
    // tls: { rejectUnauthorized: false },
  });

  // email options
  const mailOptions = {
    from: `"Website Contact" <${process.env.SMTP_USER}>`, // use your domain mailbox
    to: process.env.SMTP_USER, // receive in same mailbox
    subject: `New contact from ${cName}`,
    text: `Name: ${cName}\nEmail: ${cEmail}\n\nMessage:\n${cMessage}`,
    replyTo: `${cName} <${cEmail}>`,
  };

  try {
    await transporter.sendMail(mailOptions);
    return res.json({ ok: true });
  } catch (err) {
    console.error('Mail send error:', err);
    return res.status(500).json({ ok: false, error: 'Send failed' });
  }
}
