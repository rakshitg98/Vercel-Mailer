import nodemailer from 'nodemailer';

// --- Config: rate limit / window
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

// --- Helper: attach CORS headers to response
function setCorsHeaders(res, origin) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  // If you need cookies/authorization headers, enable credentials:
  // res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// --- Main handler
export default async function handler(req, res) {
  const allowedOrigin = process.env.ALLOWED_ORIGIN || '*';
  // For security prefer exact origin (e.g., https://username.github.io)
  const requestOrigin = req.headers.origin || allowedOrigin;
  const originToUse = allowedOrigin === '*' ? '*' : (requestOrigin === allowedOrigin ? allowedOrigin : '');

  // Always set CORS headers (use empty originToUse to block if not allowed)
  setCorsHeaders(res, originToUse || ''); // if empty string, browser will treat as not allowed

  // Preflight handling
  if (req.method === 'OPTIONS') {
    // Respond to preflight quickly
    return res.status(204).end();
  }

  // Only allow POST for the mail flow
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  // Optional: block if origin not allowed
  if (!allowedOrigin) {
    console.warn('No ALLOWED_ORIGIN set; request origins are not restricted.');
  } else if (allowedOrigin !== '*' && requestOrigin !== allowedOrigin) {
    // If request's Origin header doesn't match configured allowed origin, reject
    return res.status(403).json({ ok: false, error: 'Origin not allowed' });
  }

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!rateLimitOk(ip)) return res.status(429).json({ ok: false, error: 'Too many requests' });

  const { name = '', email = '', message = '', _gotcha = '' } = req.body || {};

  // Honeypot (spam) check
  if (_gotcha) return res.status(200).json({ ok: true, spam: true });

  // Basic validation
  const clean = s => String(s || '').replace(/[<>]/g, '').trim();
  const cName = clean(name);
  const cEmail = clean(email);
  const cMessage = String(message || '').trim();

  if (!cName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cEmail) || !cMessage) {
    return res.status(400).json({ ok: false, error: 'Invalid input' });
  }

  // Check SMTP credentials are set
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.error('SMTP credentials missing:', {
      smtp_user_set: !!process.env.SMTP_USER,
      smtp_pass_set: !!process.env.SMTP_PASS
    });
    return res.status(500).json({ ok: false, error: 'Server misconfigured: SMTP credentials missing' });
  }

  // Create transporter
  const transporter = nodemailer.createTransport({
    host: 'smtpout.secureserver.net',
    port: 465,        // TLS port; use 465 + secure:true if needed
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  // Optional verify to get immediate, clear error logs
  try {
    await transporter.verify();
  } catch (err) {
    console.error('SMTP verify failed:', err);
    return res.status(500).json({ ok: false, error: 'SMTP connection/auth failed' });
  }

  const mailOptions = {
    from: `"Website Contact" <${process.env.SMTP_USER}>`,
    to: process.env.SMTP_USER,
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
