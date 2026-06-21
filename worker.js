/**
 * Wissely Core API Worker - Production Ready Delivery Module
 * Features: PBKDF2 Hashing, Secure HttpOnly Sessions, Subscription Limits,
 * CORS Verification, and Hardened Security Response Headers
 */

// Explicit allowed origin whitelist for secure CORS isolation
const ALLOWED_ORIGINS = [
  'https://wissely.com',
  'https://www.wissely.com',
  'https://app.wissely.com',
  'https://wissely-worker.thilinarashmika0727.workers.dev'
];

// Input length hard limits
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 1024;
const MAX_TOKEN_LENGTH = 512;

// Rate limiting config (requests per window per IP)
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_REQUESTS = 10;

// Security headers applied to every response (API-appropriate CSP, no inline/script
// execution surface since this worker only ever returns JSON or an empty body).
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'Cross-Origin-Resource-Policy': 'same-site'
};

function getAllowedOrigin(request) {
  const origin = request.headers.get('Origin');
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    return origin;
  }
  return ALLOWED_ORIGINS[0];
}

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hexString) {
  const matches = hexString.match(/.{1,2}/g) || [];
  return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
}

// Constant-time string comparison to prevent timing attacks
function safeCompare(a, b) {
  const encodedA = new TextEncoder().encode(a);
  const encodedB = new TextEncoder().encode(b);
  if (encodedA.length !== encodedB.length) return false;
  let diff = 0;
  for (let i = 0; i < encodedA.length; i++) diff |= encodedA[i] ^ encodedB[i];
  return diff === 0;
}

// SHA-256 hash a reset token before DB storage
async function hashToken(token) {
  const encoded = new TextEncoder().encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return bufToHex(hashBuffer);
}

async function hashPassword(password, givenSalt = null) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const salt = givenSalt ? hexToBuf(givenSalt) : crypto.getRandomValues(new Uint8Array(16));

  const baseKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  );

  const exportedKey = await crypto.subtle.exportKey('raw', derivedKey);
  return { hash: bufToHex(exportedKey), salt: bufToHex(salt) };
}

// Generate a cryptographically secure mixed-case alphanumeric reset token
function generateResetToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  return Array.from(bytes)
    .map(b => chars[b % chars.length])
    .join('');
}

function createResponse(request, data, status = 200, headers = {}) {
  const origin = getAllowedOrigin(request);
  const corsHeaders = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers': 'Set-Cookie',
    // Ensures shared/edge caches don't serve one origin's CORS headers to another origin
    'Vary': 'Origin',
    // API responses (including auth/session data) should never be cached
    'Cache-Control': 'no-store'
  };
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, ...SECURITY_HEADERS, ...headers }
  });
}

function parseCookies(request) {
  const list = {};
  const rc = request.headers.get('Cookie');
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

// Safe JSON body parser — returns 400 instead of 500 on malformed input
async function parseJsonBody(request) {
  try {
    return { body: await request.json(), error: null };
  } catch {
    return { body: null, error: 'Invalid JSON in request body' };
  }
}

// IP-based rate limiter using Cloudflare KV
async function checkRateLimit(request, env, key) {
  if (!env.RATE_LIMIT_KV) return false; // skip if KV not bound
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const kvKey = `rl:${key}:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowKey = Math.floor(now / RATE_LIMIT_WINDOW_SECONDS);
  const fullKey = `${kvKey}:${windowKey}`;

  try {
    const current = await env.RATE_LIMIT_KV.get(fullKey);
    const count = current ? parseInt(current) : 0;
    if (count >= RATE_LIMIT_MAX_REQUESTS) return true; // rate limited
    await env.RATE_LIMIT_KV.put(fullKey, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW_SECONDS * 2 });
    return false;
  } catch {
    return false; // fail open — never block on KV errors
  }
}

async function authenticateSession(request, env) {
  const cookies = parseCookies(request);
  const sessionId = cookies['wissely_session'];
  if (!sessionId) return null;

  const session = await env.DB.prepare(
    "SELECT s.id AS session_id, s.expires_at, u.id AS user_id, u.email, u.plan, u.analyses_used, u.analyses_limit, u.trial_end " +
    "FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?"
  ).bind(sessionId).first();

  if (!session) return null;

  if (new Date().getTime() > new Date(session.expires_at).getTime()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
    return null;
  }

  if (session.plan === 'trial' && new Date().getTime() > new Date(session.trial_end).getTime()) {
    session.isExpiredTrial = true;
  }

  return session;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      const origin = getAllowedOrigin(request);
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Allow-Credentials': 'true',
          // Lets browsers cache the preflight result, cutting down on extra round trips
          'Access-Control-Max-Age': '86400',
          'Vary': 'Origin',
          ...SECURITY_HEADERS
        }
      });
    }

    try {
      // Non-blocking background housekeeping via waitUntil — does not delay response
      if (Math.random() < 0.05) {
        const nowIso = new Date().toISOString();
        ctx.waitUntil(
          env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(nowIso).run()
        );
      }

      // ── REGISTER ────────────────────────────────────────────────────────────
      if (path === '/register' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'register')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email, password } = body;
        if (!email || !password) return createResponse(request, { error: 'Email and password required' }, 400);

        // Input length guards
        if (email.length > MAX_EMAIL_LENGTH) return createResponse(request, { error: 'Email address is too long' }, 400);
        if (password.length > MAX_PASSWORD_LENGTH) return createResponse(request, { error: 'Password is too long' }, 400);
        if (password.length < 8) return createResponse(request, { error: 'Password must be at least 8 characters' }, 400);

        // Basic email format check
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return createResponse(request, { error: 'Invalid email address' }, 400);
        }

        const targetUser = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
        if (targetUser) return createResponse(request, { error: 'Email already registered' }, 409);

        const id = crypto.randomUUID();
        const { hash, salt } = await hashPassword(password);
        const trialEnd = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

        await env.DB.prepare(
          "INSERT INTO users (id, email, password_hash, password_salt, plan, analyses_used, analyses_limit, trial_end, created_at) " +
          "VALUES (?, ?, ?, ?, 'trial', 0, 20, ?, ?)"
        ).bind(id, email, hash, salt, trialEnd, new Date().toISOString()).run();

        return createResponse(request, { success: true, message: 'User registered successfully' }, 201);
      }

      // ── LOGIN ────────────────────────────────────────────────────────────────
      if (path === '/login' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'login')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email, password } = body;
        if (!email || !password) return createResponse(request, { error: 'Fields required' }, 400);

        // Input length guards
        if (email.length > MAX_EMAIL_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
          return createResponse(request, { error: 'Invalid email or password' }, 401);
        }

        const user = await env.DB.prepare(
          "SELECT id, email, password_hash, password_salt, plan, analyses_used, analyses_limit FROM users WHERE email = ?"
        ).bind(email).first();

        if (!user) return createResponse(request, { error: 'Invalid email or password' }, 401);

        const { hash } = await hashPassword(password, user.password_salt);

        // Constant-time comparison prevents timing attacks
        if (!safeCompare(hash, user.password_hash)) {
          return createResponse(request, { error: 'Invalid email or password' }, 401);
        }

        // Invalidate all previous sessions on new login
        await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id).run();

        const sessionId = crypto.randomUUID();
        const expiresAtDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").bind(sessionId, user.id, expiresAtDate.toISOString()).run();

        const cookieStr = [
          `wissely_session=${sessionId}`,
          `Expires=${expiresAtDate.toUTCString()}`,
          'HttpOnly',
          'Path=/',
          'SameSite=None',
          'Secure'
        ].join('; ');

        return createResponse(request, {
          success: true,
          user: { id: user.id, email: user.email, plan: user.plan, analyses_used: user.analyses_used, analyses_limit: user.analyses_limit }
        }, 200, { 'Set-Cookie': cookieStr });
      }

      // ── FORGOT PASSWORD ──────────────────────────────────────────────────────
      if (path === '/forgot-password' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'forgot-password')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email } = body;
        if (!email) return createResponse(request, { error: 'Email required' }, 400);
        if (email.length > MAX_EMAIL_LENGTH) {
          // Return standard response to prevent enumeration
          return createResponse(request, { success: true, message: 'If the provided account exists, a reset link has been sent.' }, 200);
        }

        const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();

        // Prevent email enumeration: return standard success payload even if user does not exist
        if (user) {
          // Raw token sent in email; hashed token stored in DB
          const rawToken = generateResetToken();
          const hashedToken = await hashToken(rawToken);

          const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
          const createdAt = new Date().toISOString();

          // Delete any previously outstanding tokens for this user
          await env.DB.prepare("DELETE FROM password_resets WHERE user_id = ?").bind(user.id).run();

          // Store the hashed token — raw token never touches the database
          await env.DB.prepare(
            "INSERT INTO password_resets (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
          ).bind(hashedToken, user.id, expiresAt, createdAt).run();

          // Send notification email with Resend API Integration
          try {
            const resetLink = `https://app.wissely.com/reset-password.html?token=${rawToken}`;

            const htmlEmail = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Reset your Wissely password</title>
</head>
<body style="margin:0;padding:0;background-color:#0c0c0a;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0c0a;padding:48px 16px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;">
          <tr>
            <td style="padding-bottom:28px;" align="center">
              <table cellpadding="0" cellspacing="0">
                <tr>
                  <td style="width:32px;height:32px;background-color:#2d4a3e;border-radius:7px;text-align:center;vertical-align:middle;">
                    <span style="font-family:Georgia,serif;font-size:16px;font-weight:700;color:#e8c97a;line-height:32px;">W</span>
                  </td>
                  <td style="padding-left:10px;vertical-align:middle;">
                    <span style="font-family:Georgia,serif;font-size:22px;font-weight:700;color:#fefefc;letter-spacing:-0.5px;">Wissely</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:#1a1a14;border:1px solid rgba(255,255,255,0.07);border-radius:18px;overflow:hidden;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="height:3px;background:linear-gradient(90deg,#2d4a3e,#c9a84c,#2d4a3e);"></td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:40px 40px 36px;">
                    <p style="margin:0 0 18px;font-size:10px;font-family:'Courier New',monospace;letter-spacing:3px;text-transform:uppercase;color:#c9a84c;font-weight:600;">Password Reset</p>
                    <h1 style="margin:0 0 14px;font-family:Georgia,serif;font-size:32px;font-weight:600;color:#fefefc;letter-spacing:-1px;line-height:1.1;">
                      Reset your<br/><em style="font-style:italic;color:#e8c97a;">password.</em>
                    </h1>
                    <p style="margin:0 0 32px;font-size:14px;color:rgba(255,255,255,0.6);line-height:1.85;">
                      We received a request to reset the password for your Wissely account. Click the button below to choose a new one.
                    </p>
                    <table cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
                      <tr>
                        <td style="background-color:#c9a84c;border-radius:100px;">
                          <a href="${resetLink}"
                             style="display:inline-block;padding:14px 36px;font-size:14px;font-weight:600;color:#0c0c0a;text-decoration:none;font-family:'Segoe UI',Arial,sans-serif;letter-spacing:0.2px;">
                            Reset Password
                          </a>
                        </td>
                      </tr>
                    </table>
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
                      <tr>
                        <td style="background-color:rgba(45,74,62,0.25);border:1px solid rgba(45,74,62,0.45);border-left:3px solid #c9a84c;border-radius:10px;padding:14px 18px;">
                          <p style="margin:0;font-size:12px;color:rgba(255,255,255,0.6);line-height:1.6;font-family:'Courier New',monospace;">
                            <span style="color:#e8c97a;font-weight:600;">&#9679; EXPIRES IN 1 HOUR</span><br/>
                            If you did not request this, you can safely ignore this email. Your password will not change.
                          </p>
                        </td>
                      </tr>
                    </table>
                    <p style="margin:0;font-size:12px;color:rgba(255,255,255,0.35);line-height:1.7;">
                      Button not working? Copy and paste this link:<br/>
                      <a href="${resetLink}" style="color:#c9a84c;text-decoration:none;word-break:break-all;">${resetLink}</a>
                    </p>
                  </td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="border-top:1px solid rgba(255,255,255,0.05);padding:24px 40px;">
                    <p style="margin:0 0 6px;font-size:10px;font-family:'Courier New',monospace;letter-spacing:3px;text-transform:uppercase;color:#c9a84c;font-weight:600;">Need help?</p>
                    <p style="margin:0;font-size:13px;color:rgba(255,255,255,0.45);line-height:1.7;">
                      Contact us at&nbsp;<a href="mailto:support@wissely.com" style="color:#c9a84c;text-decoration:none;font-weight:500;">support@wissely.com</a>
                    </p>
                  </td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="border-top:1px solid rgba(255,255,255,0.05);padding:20px 40px;">
                    <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.3);font-family:'Courier New',monospace;line-height:1.6;">
                      &copy; ${new Date().getFullYear()} Wissely. All rights reserved.<br/>
                      You received this email because a password reset was requested for your Wissely account.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

            // Resend with one retry on transient failure
            let resendRes = await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${env.RESEND_API_KEY}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                from: 'Wissely <noreply@wissely.com>',
                to: [email],
                subject: 'Reset your Wissely password',
                html: htmlEmail,
                text: `Reset your password: ${resetLink}`
              })
            });

            if (!resendRes.ok) {
              // Single retry on failure
              resendRes = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                  'Authorization': `Bearer ${env.RESEND_API_KEY}`,
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  from: 'Wissely <noreply@wissely.com>',
                  to: [email],
                  subject: 'Reset your Wissely password',
                  html: htmlEmail,
                  text: `Reset your password: ${resetLink}`
                })
              });

              if (!resendRes.ok) {
                const errorText = await resendRes.text();
                console.error(`[PASSWORD RESET] Resend failed after retry: ${resendRes.status} - ${errorText}`);
              }
            }
          } catch (emailError) {
            console.error('[PASSWORD RESET] Email dispatch exception:', emailError);
          }
        }

        return createResponse(request, {
          success: true,
          message: 'If the provided account exists, a reset link has been sent.'
        }, 200);
      }

      // ── RESET PASSWORD ───────────────────────────────────────────────────────
      if (path === '/reset-password' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'reset-password')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { token, password } = body;
        if (!token || !password) return createResponse(request, { error: 'Token and password are required' }, 400);

        // Input length guards
        if (token.length > MAX_TOKEN_LENGTH) return createResponse(request, { error: 'Invalid reset token' }, 400);
        if (password.length > MAX_PASSWORD_LENGTH) return createResponse(request, { error: 'Password is too long' }, 400);
        if (password.length < 8) return createResponse(request, { error: 'Password must be at least 8 characters' }, 400);

        // Hash the incoming raw token to look up the stored hashed token
        const hashedToken = await hashToken(token);

        const resetRecord = await env.DB.prepare(
          "SELECT token, user_id, expires_at FROM password_resets WHERE token = ?"
        ).bind(hashedToken).first();

        if (!resetRecord) {
          return createResponse(request, { error: 'Invalid or expired reset link' }, 400);
        }

        if (new Date().getTime() > new Date(resetRecord.expires_at).getTime()) {
          await env.DB.prepare("DELETE FROM password_resets WHERE token = ?").bind(hashedToken).run();
          return createResponse(request, { error: 'Reset link has expired. Please request a new one.' }, 400);
        }

        const { hash, salt } = await hashPassword(password);

        // Batch: update password, invalidate all sessions, delete reset token
        await env.DB.batch([
          env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?").bind(hash, salt, resetRecord.user_id),
          env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(resetRecord.user_id),
          env.DB.prepare("DELETE FROM password_resets WHERE user_id = ?").bind(resetRecord.user_id)
        ]);

        return createResponse(request, {
          success: true,
          message: 'Password updated successfully. Please log in with your new password.'
        }, 200);
      }

      // ── ME ───────────────────────────────────────────────────────────────────
      if (path === '/me' && request.method === 'GET') {
        const session = await authenticateSession(request, env);
        if (!session) return createResponse(request, { error: 'Unauthenticated' }, 401);
        
        if (session.isExpiredTrial) {
          return createResponse(request, {
            authenticated: true,
            trialExpired: true,
            user: {
              id: session.user_id,
              email: session.email,
              plan: session.plan,
              analyses_used: session.analyses_used,
              analyses_limit: session.analyses_limit,
              trial_end: session.trial_end
            }
          }, 403);
        }

        return createResponse(request, {
          authenticated: true,
          user: { 
            id: session.user_id, 
            email: session.email, 
            plan: session.plan, 
            analyses_used: session.analyses_used, 
            analyses_limit: session.analyses_limit,
            trial_end: session.trial_end
          }
        });
      }

      // ── LOGOUT ───────────────────────────────────────────────────────────────
      if (path === '/logout' && request.method === 'POST') {
        const cookies = parseCookies(request);
        const sessionId = cookies['wissely_session'];
        if (sessionId) {
          await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
        }
        return createResponse(request, { success: true }, 200, {
          'Set-Cookie': 'wissely_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure'
        });
      }

      // ── ANALYZE ──────────────────────────────────────────────────────────────
      if (path === '/analyze' && request.method === 'POST') {
        const session = await authenticateSession(request, env);
        if (!session) return createResponse(request, { error: 'Unauthorized' }, 401);
        if (session.isExpiredTrial) return createResponse(request, { error: 'Trial expired' }, 403);

        const allocation = await env.DB.prepare(
          "UPDATE users SET analyses_used = analyses_used + 1 WHERE id = ? AND analyses_used < analyses_limit"
        ).bind(session.user_id).run();

        if (allocation.meta.changes === 0) {
          return createResponse(request, { error: 'Usage limit reached for this month' }, 403);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) {
          await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
          return createResponse(request, { error: parseError }, 400);
        }

        if (!body.messages) {
          await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
          return createResponse(request, { error: 'Missing messages field' }, 400);
        }

        try {
          const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': env.ANTHROPIC_API_KEY,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1000, messages: body.messages })
          });

          const rawPayload = await anthropicRes.text();

          let data;
          try {
            data = JSON.parse(rawPayload);
          } catch (e) {
            data = { rawTextFallback: rawPayload };
          }

          if (anthropicRes.ok) {
            const updatedUser = await env.DB.prepare(`
              SELECT
                id,
                email,
                plan,
                analyses_used,
                analyses_limit,
                trial_end
              FROM users
              WHERE id = ?
            `).bind(session.user_id).first();

            return createResponse(request, {
              success: true,
              data,
              user: updatedUser
            });
          } else {
            await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
            return createResponse(request, { error: 'Analysis service unavailable. Please try again.' }, 502);
          }
        } catch (apiError) {
          await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
          console.error('[Analyze] Upstream fetch failed:', apiError.message);
          throw apiError;
        }
      }

      return createResponse(request, { error: 'Not found' }, 404);
    } catch (globalError) {
      console.error('[Worker] Unhandled exception:', globalError.message);
      return createResponse(request, { error: 'An unexpected error occurred' }, 500);
    }
  }
};
