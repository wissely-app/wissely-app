/**
 * Wissely Core API Worker — Enterprise Production Build
 *
 * Features:
 *   Authentication     — PBKDF2/SHA-256 passwords, hashed session IDs, HttpOnly cookies
 *   Session security   — Per-session CSRF tokens, hashed session storage, 7-day expiry
 *   CSRF protection    — X-CSRF-Token header validation on every state-changing endpoint
 *   Rate limiting      — Per-IP sliding-window via Cloudflare KV
 *   Login protection   — Per-IP + per-account brute-force blocking with auto-expiry
 *   Audit logging      — Structured security event log with 90-day retention
 *   AI integration     — Anthropic claude-sonnet-4-6, 60s timeout, exponential-backoff retry
 *   AI validation      — Schema-enforced report normalisation, malformed-output handling
 *   Email delivery     — Resend API, background via waitUntil(), automatic retry
 *   Paddle Billing v2  — HMAC-SHA256 webhook verification, idempotency, full event set
 *   Subscriptions      — Starter / Growth / Pro plans, atomic quota management
 *   Checkout           — Server-side Paddle transaction creation for hosted checkout
 *   Cleanup            — Daily stale-data purge (5 % per-request) + monthly cron
 *   Security headers   — HSTS, CSP, CORP, X-Frame, Referrer, Permissions-Policy
 *   Request tracing    — X-Request-ID propagated through every log line
 *   Database           — D1 batch/atomic operations, index-aware queries
 */

'use strict';

// ── CONFIGURATION ────────────────────────────────────────────────────────────

const ALLOWED_ORIGINS = [
  'https://wissely.com',
  'https://www.wissely.com',
  'https://app.wissely.com',
  'https://wissely-worker.thilinarashmika0727.workers.dev'
];

// Hard input length limits
const MAX_EMAIL_LENGTH    = 254;
const MAX_PASSWORD_LENGTH = 1024;
const MAX_TOKEN_LENGTH    = 512;

// General rate limiter — 10 requests per IP per 60-second window
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_REQUESTS   = 10;

// Failed-login protection — tracked independently from the general limiter.
// Two-key strategy: per-IP and per-email so both credential-stuffing (many
// accounts from one IP) and targeted attacks (one account from many IPs) are caught.
const LOGIN_FAIL_WINDOW_SECONDS = 900;  // 15-minute rolling window
const LOGIN_BLOCK_THRESHOLD     = 10;   // failures before a block is issued
const LOGIN_BLOCK_TTL_SECONDS   = 1800; // 30-minute block duration

// CSRF-failure threshold — repeated failures from the same IP are treated as
// a probing attack and surfaced as a high-severity audit event.
const CSRF_FAIL_WINDOW_SECONDS  = 300;  // 5-minute window
const CSRF_FAIL_ALERT_THRESHOLD = 5;    // failures before alert audit event

// Webhook-signature-failure threshold — same pattern as CSRF monitoring.
const WEBHOOK_FAIL_WINDOW_SECONDS  = 300;
const WEBHOOK_FAIL_ALERT_THRESHOLD = 3;

// AI integration
const MAX_AI_PAYLOAD_BYTES  = 102400; // 100 KB — rejected before quota consumed
const ANTHROPIC_TIMEOUT_MS  = 60000; // 60 s
const ANTHROPIC_MAX_RETRIES = 1;     // one retry on 429 / 5xx with backoff
const ANTHROPIC_RETRY_DELAY = 2000;  // 2 s initial backoff (doubled on each retry)

// Paddle idempotency — event IDs stored in KV for 24 h to detect re-deliveries
const PADDLE_EVENT_KV_PREFIX   = 'paddle_event:';
const PADDLE_EVENT_TTL_SECONDS = 86400;

// Paddle checkout creation — subrequest timeout to the Paddle Transactions API
const PADDLE_CHECKOUT_TIMEOUT_MS = 10000; // 10 s

// Paddle customer lookup — subrequest timeout for resolving an account from
// a webhook event when custom_data.user_id is not present.
const PADDLE_CUSTOMER_LOOKUP_TIMEOUT_MS = 8000; // 8 s

// Paddle customer portal — subrequest timeout to the Portal Sessions API.
const PADDLE_PORTAL_TIMEOUT_MS = 8000; // 8 s

// Audit log retention — records older than this are pruned by the monthly cron
const AUDIT_RETENTION_DAYS = 90;

// ── SECURITY HEADERS ─────────────────────────────────────────────────────────
// Applied to every response. Worker returns JSON only, so CSP allows nothing.

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'strict-origin-when-cross-origin',
  'Permissions-Policy':        'geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
  'Content-Security-Policy':   "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'Cross-Origin-Resource-Policy': 'same-site'
};

// ── PADDLE PLAN CONFIGURATION ─────────────────────────────────────────────────
// In Paddle Billing v2 webhook payloads the price ID lives at:
//   data.items[N].price.id   (full price object, not a flat price_id field)
// resolvePaddlePlan() scans all items so multi-item subscriptions are handled.

const PADDLE_PRICE_PLANS = {
  'pri_01kvx9ybw6crh3pswgsj2wq39c': { plan: 'starter', analyses_limit: 50   },
  'pri_01kvxa3n164k0zrrjte8sg17n9': { plan: 'growth',  analyses_limit: 250  },
  'pri_01kvxa5v3s82pe1fw3h71wb4e9': { plan: 'pro',     analyses_limit: 1000 },
};

// Reverse lookup — plan name to price ID, used when creating a checkout
// transaction. Built once from PADDLE_PRICE_PLANS so the two maps can never
// drift out of sync with each other.
const PLAN_TO_PRICE_ID = Object.entries(PADDLE_PRICE_PLANS).reduce((acc, [priceId, cfg]) => {
  acc[cfg.plan] = priceId;
  return acc;
}, {});

// Applied on cancellation, pause, or unrecognised price ID
const PLAN_FREE = { plan: 'free', analyses_limit: 5 };

// ── AI PROMPTS ────────────────────────────────────────────────────────────────

const AI_BASE_SYSTEM_PROMPT = `You are a financial analysis AI for Wissely, a professional financial intelligence platform.

STRICT OUTPUT RULES:
- Return ONLY valid JSON. Nothing else.
- Never wrap output in markdown code fences.
- Never include \`\`\`json or \`\`\` anywhere.
- Never explain your reasoning.
- Never include introductory or closing text.
- Never include HTML, markdown tables, bullet lists, code blocks, or comments outside the JSON.
- The response must begin with { and end with }.

REQUIRED JSON SCHEMA:
You must always return this exact structure:
{
  "schemaVersion": "1.0",
  "tool": "<name of the Wissely tool being used>",
  "title": "<concise report title>",
  "status": "completed",
  "generatedAt": "<ISO 8601 timestamp>",
  "summary": "<executive-level summary, 2-4 sentences>",
  "metrics": [{ "label": "", "value": "", "unit": "" }],
  "findings": [{ "title": "", "detail": "" }],
  "risks": [{ "level": "low|medium|high", "description": "" }],
  "recommendations": [{ "priority": "low|medium|high", "action": "" }],
  "confidence": 95
}

OPTIONAL FIELDS:
Include any of these when relevant to the analysis. They must never replace the required fields above.
- invoice, vendor, customer, totals, currency, dates, paymentTerms
- expenseBreakdown, fraudIndicators, cashFlow
- charts, tables, timeline, warnings, insights

OUTPUT QUALITY:
- Summaries must be executive-level and professional.
- Recommendations must be specific and actionable.
- confidence is an integer from 0 to 100 reflecting your certainty in the analysis.
- status must be exactly one of: completed, warning, error.`;

const AI_TOOL_PROMPTS = {
  'invoice-analyzer': `TOOL: Invoice Analyzer
Your task is to extract and validate every field from the provided invoice.
Focus on:
- Vendor name, address, contact details
- Customer name and billing address
- Invoice number, invoice date, due date, and payment terms
- Line items: description, quantity, unit price, subtotal
- Tax rate, tax amount, total amount due, and currency
- Any discrepancies between subtotals and totals
- Missing or suspicious fields (blank vendor, zero totals, future-dated invoices)
- Invoice quality score and completeness
Populate the optional fields: invoice, vendor, customer, totals, dates, paymentTerms.`,

  'expense-clarity': `TOOL: Expense Clarity
Your task is to analyze the provided expense data and identify patterns and savings.
Focus on:
- Categorizing every expense by type (travel, software, payroll, marketing, etc.)
- Identifying recurring vs one-time expenses
- Detecting unusually high spending in any category
- Calculating category totals and percentage of total spend
- Surfacing concrete savings opportunities
- Identifying trends across time periods if data allows
Populate the optional fields: expenseBreakdown, categoryTotals, insights, timeline.`,

  'finance-report': `TOOL: Finance Report
Your task is to produce a concise executive financial report.
Focus on:
- Overall business financial health
- Revenue, expenses, and net profit/loss
- Profitability trends and margins
- Key financial strengths and weaknesses
- Market or operational opportunities
- Strategic recommendations for leadership
Write the summary as a boardroom-ready executive briefing.
Populate the optional fields: insights, charts, tables, warnings.`,

  'fraud-detection': `TOOL: Fraud Detection
Your task is to identify suspicious activity and fraud signals in the provided data.
Focus on:
- Duplicate invoices or payments (same amount, vendor, or date)
- Abnormally high or round-number amounts
- Vendors with missing or incomplete details
- Invoices outside normal business hours or patterns
- Payment destinations that differ from expected vendors
- Confidence score reflecting certainty of fraud risk
Set status to "warning" if moderate risk is detected, "error" if high risk.
Populate the optional field: fraudIndicators (array of specific signals found).`,

  'cash-flow-forecast': `TOOL: Cash Flow Forecast
Your task is to project future cash flow based on the provided financial data.
Focus on:
- Projected income by period (weekly or monthly)
- Projected expenses by period
- Net cash flow per period
- Estimated cash runway (how many months of runway remain)
- Identification of upcoming cash shortages or pressure points
- Recommendations to extend runway or improve cash position
Populate the optional fields: cashFlow (array of period projections), timeline, warnings.`,

  'payment-request': `TOOL: Payment Request
Your task is to analyze and improve the quality of a payment request or reminder.
Focus on:
- Professional and polite tone throughout
- Clear statement of amount owed, due date, and payment method
- Appropriate urgency without being aggressive
- Customer-friendly language that preserves the business relationship
- Completeness: all required payment details present
- Recommendations for improving the payment request wording
Populate findings with specific wording improvements and recommendations with actionable next steps.`
};

// Returns the merged system prompt for the requested tool.
// Falls back to the base prompt for unregistered tool names.
function buildSystemPrompt(toolName) {
  const ext = AI_TOOL_PROMPTS[toolName];
  return ext ? AI_BASE_SYSTEM_PROMPT + '\n\n' + ext : AI_BASE_SYSTEM_PROMPT;
}

// ── CRYPTOGRAPHIC UTILITIES ───────────────────────────────────────────────────

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hex) {
  const pairs = hex.match(/.{1,2}/g) || [];
  return new Uint8Array(pairs.map(b => parseInt(b, 16)));
}

// Constant-time comparison — prevents timing oracle attacks on token equality checks.
// Both inputs are encoded to Uint8Array so Unicode characters do not bypass the check.
function safeCompare(a, b) {
  const enc  = new TextEncoder();
  const bufA = enc.encode(String(a));
  const bufB = enc.encode(String(b));
  if (bufA.length !== bufB.length) return false;
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
  return diff === 0;
}

// SHA-256 of an arbitrary string — used for session IDs, reset tokens, and
// email verification tokens so raw secrets never reach the database.
async function hashToken(token) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return bufToHex(buf);
}

// PBKDF2-HMAC-SHA256 password hashing — 100 000 iterations, 128-bit random salt.
// When givenSalt is provided (login path) the same salt is reused for verification.
async function hashPassword(password, givenSalt = null) {
  const pwBuf  = new TextEncoder().encode(password);
  const salt   = givenSalt ? hexToBuf(givenSalt) : crypto.getRandomValues(new Uint8Array(16));
  const base   = await crypto.subtle.importKey('raw', pwBuf, 'PBKDF2', false, ['deriveKey']);
  const derived = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    base,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true, ['sign']
  );
  const raw = await crypto.subtle.exportKey('raw', derived);
  return { hash: bufToHex(raw), salt: bufToHex(salt) };
}

// Cryptographically secure 48-character alphanumeric token (Web Crypto only).
// Used for: session IDs, CSRF tokens, reset tokens, verification tokens.
// The modulo bias is negligible: charset length 62, byte range 0-255, max bias < 0.5 %.
function generateSecureToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

// Legacy alias kept for internal call-site consistency
const generateResetToken = generateSecureToken;

// ── NETWORK / REQUEST UTILITIES ───────────────────────────────────────────────

// Returns the first CORS-allowed origin, or the request's Origin if whitelisted.
function getAllowedOrigin(request) {
  const origin = request.headers.get('Origin');
  return (origin && ALLOWED_ORIGINS.includes(origin)) ? origin : ALLOWED_ORIGINS[0];
}

// CF-Connecting-IP is always present on inbound requests processed by Cloudflare.
function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// Parses the Cookie header into a plain { name: value } object.
function parseCookies(request) {
  const jar = {};
  const raw = request.headers.get('Cookie');
  if (!raw) return jar;
  for (const pair of raw.split(';')) {
    const eq  = pair.indexOf('=');
    if (eq < 1) continue;
    const key = pair.slice(0, eq).trim();
    const val = pair.slice(eq + 1).trim();
    try { jar[key] = decodeURIComponent(val); } catch { jar[key] = val; }
  }
  return jar;
}

// Safe JSON body parser — never throws; returns a structured result object.
async function parseJsonBody(request) {
  try {
    return { body: await request.json(), error: null };
  } catch {
    return { body: null, error: 'Invalid JSON in request body' };
  }
}

// Builds the JSON response with unified CORS + security headers.
// An optional extra-headers object is merged last so callers can add Set-Cookie etc.
function createResponse(request, data, status = 200, extraHeaders = {}) {
  const origin = getAllowedOrigin(request);
  const headers = {
    'Content-Type':                     'application/json',
    'Access-Control-Allow-Origin':      origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers':    'Set-Cookie',
    'Vary':                             'Origin',
    'Cache-Control':                    'no-store',
    ...SECURITY_HEADERS,
    ...extraHeaders
  };
  return new Response(JSON.stringify(data), { status, headers });
}

// ── AUDIT LOGGING ─────────────────────────────────────────────────────────────
// Structured security-event log. Never throws — a logging failure must never
// affect the API response. Accepts an optional requestId for correlation.

async function writeAuditLog(env, {
  requestId = null,
  userId    = null,
  ip        = 'unknown',
  eventType,
  result,
  metadata  = null
}) {
  try {
    await env.DB.prepare(
      'INSERT INTO audit_logs (id, timestamp, user_id, ip, event_type, result, metadata) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      crypto.randomUUID(),
      new Date().toISOString(),
      userId,
      ip,
      eventType,
      result,
      metadata ? JSON.stringify({ ...metadata, requestId }) : (requestId ? JSON.stringify({ requestId }) : null)
    ).run();
  } catch (err) {
    // Console-only — never propagate
    console.error('[Audit] Write failed:', err.message, { eventType, result });
  }
}

// ── SECURITY MONITORING HELPERS ───────────────────────────────────────────────
// Increment a per-IP abuse counter in KV and emit a high-severity audit event
// once the threshold is crossed. Used for CSRF probing and webhook replay attempts.

async function trackSecurityFailure(env, request, {
  kvPrefix,
  windowSeconds,
  threshold,
  alertEventType,
  requestId
}) {
  if (!env.RATE_LIMIT_KV) return;
  const ip       = getClientIp(request);
  const window   = Math.floor(Date.now() / 1000 / windowSeconds);
  const kvKey    = `${kvPrefix}:${ip}:${window}`;

  try {
    const raw   = await env.RATE_LIMIT_KV.get(kvKey);
    const count = raw ? parseInt(raw, 10) + 1 : 1;
    await env.RATE_LIMIT_KV.put(kvKey, String(count), { expirationTtl: windowSeconds * 2 });

    if (count === threshold) {
      // Fire the alert audit event exactly once per window crossing
      await writeAuditLog(env, {
        requestId,
        ip,
        eventType: alertEventType,
        result:    'alert',
        metadata:  { count, windowSeconds }
      });
      console.warn(`[Security] Threshold crossed for ${alertEventType}`, { ip, count });
    }
  } catch {
    // Non-fatal
  }
}

// ── RATE LIMITER ──────────────────────────────────────────────────────────────
// Sliding-window counter stored in KV. Fails open on KV errors so a KV outage
// never takes the API offline.

async function checkRateLimit(request, env, key) {
  if (!env.RATE_LIMIT_KV) return false;
  const ip      = getClientIp(request);
  const window  = Math.floor(Date.now() / 1000 / RATE_LIMIT_WINDOW_SECONDS);
  const kvKey   = `rl:${key}:${ip}:${window}`;

  try {
    const raw   = await env.RATE_LIMIT_KV.get(kvKey);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= RATE_LIMIT_MAX_REQUESTS) return true;
    await env.RATE_LIMIT_KV.put(kvKey, String(count + 1), {
      expirationTtl: RATE_LIMIT_WINDOW_SECONDS * 2
    });
    return false;
  } catch {
    return false;
  }
}

// ── FAILED-LOGIN PROTECTION ───────────────────────────────────────────────────

async function checkLoginBlock(request, env, email) {
  if (!env.RATE_LIMIT_KV) return false;
  const ip = getClientIp(request);
  try {
    const [ipBlock, emailBlock] = await Promise.all([
      env.RATE_LIMIT_KV.get(`login_block:ip:${ip}`),
      env.RATE_LIMIT_KV.get(`login_block:email:${email}`)
    ]);
    return ipBlock === 'blocked' || emailBlock === 'blocked';
  } catch {
    return false;
  }
}

async function recordLoginFailure(request, env, email) {
  if (!env.RATE_LIMIT_KV) return;
  const ip      = getClientIp(request);
  const window  = Math.floor(Date.now() / 1000 / LOGIN_FAIL_WINDOW_SECONDS);
  const ipKey   = `login_fail:ip:${ip}:${window}`;
  const emailKey = `login_fail:email:${email}:${window}`;
  const ttl     = LOGIN_FAIL_WINDOW_SECONDS * 2;

  try {
    const [ipRaw, emailRaw] = await Promise.all([
      env.RATE_LIMIT_KV.get(ipKey),
      env.RATE_LIMIT_KV.get(emailKey)
    ]);
    const ipCount    = ipRaw    ? parseInt(ipRaw, 10)    + 1 : 1;
    const emailCount = emailRaw ? parseInt(emailRaw, 10) + 1 : 1;

    const writes = [
      env.RATE_LIMIT_KV.put(ipKey,    String(ipCount),    { expirationTtl: ttl }),
      env.RATE_LIMIT_KV.put(emailKey, String(emailCount), { expirationTtl: ttl })
    ];
    if (ipCount    >= LOGIN_BLOCK_THRESHOLD) writes.push(env.RATE_LIMIT_KV.put(`login_block:ip:${ip}`,       'blocked', { expirationTtl: LOGIN_BLOCK_TTL_SECONDS }));
    if (emailCount >= LOGIN_BLOCK_THRESHOLD) writes.push(env.RATE_LIMIT_KV.put(`login_block:email:${email}`, 'blocked', { expirationTtl: LOGIN_BLOCK_TTL_SECONDS }));
    await Promise.all(writes);
  } catch {
    // Non-fatal
  }
}

async function clearLoginFailures(request, env, email) {
  if (!env.RATE_LIMIT_KV) return;
  const ip = getClientIp(request);
  try {
    await Promise.all([
      env.RATE_LIMIT_KV.delete(`login_block:ip:${ip}`),
      env.RATE_LIMIT_KV.delete(`login_block:email:${email}`)
    ]);
  } catch {
    // Non-fatal
  }
}

// ── SESSION MANAGEMENT ────────────────────────────────────────────────────────
// Session IDs are hashed with SHA-256 before database storage (same pattern as
// password-reset and verification tokens). The raw token travels only in the
// HttpOnly cookie and is never stored in plaintext.

async function authenticateSession(request, env) {
  const cookies   = parseCookies(request);
  const rawId     = cookies['wissely_session'];
  if (!rawId) return null;

  // Hash the cookie value before querying — the DB stores only the hash
  const sessionHash = await hashToken(rawId);

  const session = await env.DB.prepare(
    'SELECT s.id AS session_id, s.expires_at, s.csrf_token, ' +
    'u.id AS user_id, u.email, u.plan, u.analyses_used, u.analyses_limit, u.trial_end ' +
    'FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?'
  ).bind(sessionHash).first();

  if (!session) return null;

  const now = Date.now();

  if (now > new Date(session.expires_at).getTime()) {
    // Expired — clean up asynchronously so this path stays fast
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionHash).run();
    return null;
  }

  if (session.plan === 'trial' && now > new Date(session.trial_end).getTime()) {
    session.isExpiredTrial = true;
  }

  return session;
}

// ── CSRF PROTECTION ───────────────────────────────────────────────────────────
// Per-session CSRF token, generated at login, returned in the response body
// (NOT a cookie so the browser cannot auto-send it). The frontend stores it and
// sends it as X-CSRF-Token on every authenticated state-changing POST.
//
// Design decisions:
//   • Per-session (not per-request) for simplicity without sacrificing security
//   • Stored as plaintext in the DB — it is a bearer secret issued only via the
//     login response body and never stored in an accessible location client-side
//   • Validated with safeCompare() to prevent timing attacks
//   • Repeated failures from the same IP trigger a security-monitoring alert

async function validateCsrfToken(request, env, requestId) {
  const cookies     = parseCookies(request);
  const rawId       = cookies['wissely_session'];
  if (!rawId) return false;

  const clientToken = request.headers.get('X-CSRF-Token');
  if (!clientToken || clientToken.length > MAX_TOKEN_LENGTH) return false;

  try {
    const sessionHash = await hashToken(rawId);
    const session     = await env.DB.prepare(
      'SELECT csrf_token FROM sessions WHERE id = ?'
    ).bind(sessionHash).first();

    if (!session || !session.csrf_token) return false;
    return safeCompare(clientToken, session.csrf_token);
  } catch {
    return false;
  }
}

// ── EMAIL HELPERS ─────────────────────────────────────────────────────────────
// All email sends are fire-and-forget via ctx.waitUntil() — the API response
// is never blocked on Resend. One automatic retry on transient failure.

async function sendEmailWithRetry(env, { to, subject, html, text, logTag }) {
  const payload = JSON.stringify({
    from:    'Wissely <noreply@wissely.com>',
    to:      [to],
    subject,
    html,
    text
  });
  const headers = {
    'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    'Content-Type':  'application/json'
  };

  try {
    let res = await fetch('https://api.resend.com/emails', { method: 'POST', headers, body: payload });
    if (!res.ok) {
      res = await fetch('https://api.resend.com/emails', { method: 'POST', headers, body: payload });
      if (!res.ok) {
        const errText = await res.text().catch(() => '(unreadable)');
        console.error(`[${logTag}] Email failed after retry: ${res.status} — ${errText}`);
      } else {
        console.log(`[${logTag}] Email delivered on retry`);
      }
    }
  } catch (err) {
    console.error(`[${logTag}] Email exception:`, err.message);
  }
}

// ── AI RESPONSE EXTRACTOR ─────────────────────────────────────────────────────
// Accepts raw AI responses from any provider format and returns a plain object.
// Never throws — falls back to { rawText } when JSON cannot be extracted.

function extractAIReport(rawResponse) {
  const raw = typeof rawResponse === 'string'
    ? rawResponse
    : JSON.stringify(rawResponse);

  function tryParse(s) {
    try { return JSON.parse(s); } catch { return null; }
  }

  function stripFences(s) {
    return s.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
  }

  // Already an object — unwrap known provider envelopes
  if (typeof rawResponse === 'object' && rawResponse !== null && !Array.isArray(rawResponse)) {
    // Anthropic: { content: [{ type: 'text', text: '...' }] }
    if (Array.isArray(rawResponse.content)) {
      const block = rawResponse.content.find(b => b && typeof b.text === 'string');
      if (block) {
        const inner = tryParse(block.text) ?? tryParse(stripFences(block.text));
        return inner ?? { rawText: block.text };
      }
    }
    // OpenAI: { choices: [{ message: { content: '...' } }] }
    if (Array.isArray(rawResponse.choices) && rawResponse.choices[0]?.message?.content) {
      const content = rawResponse.choices[0].message.content;
      const inner   = tryParse(content) ?? tryParse(stripFences(content));
      return inner ?? { rawText: content };
    }
    return rawResponse;
  }

  // Raw JSON string
  const direct = tryParse(raw);
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) {
    return extractAIReport(direct);
  }

  // Fenced block
  if (raw.includes('```')) {
    const fromFence = tryParse(stripFences(raw));
    if (fromFence && typeof fromFence === 'object') return extractAIReport(fromFence);
  }

  // Cloudflare AI envelope
  const cf = tryParse(raw);
  if (cf?.result) {
    if (typeof cf.result === 'object') return extractAIReport(cf.result);
    if (typeof cf.result === 'string') {
      const inner = tryParse(cf.result) ?? tryParse(stripFences(cf.result));
      if (inner) return inner;
    }
  }

  return { rawText: raw };
}

// ── AI REPORT VALIDATOR ───────────────────────────────────────────────────────
// Normalises AI output into a guaranteed-valid Wissely Report object.
// Never throws. Malformed array entries and invalid status values are replaced
// with safe defaults. A { rawText } fallback is treated as a structural failure.

function validateAIReport(raw) {
  let report;
  if (typeof raw === 'string') {
    try { report = JSON.parse(raw); } catch { report = {}; }
  } else if (raw !== null && typeof raw === 'object') {
    report = raw;
  } else {
    report = {};
  }

  const VALID_STATUSES  = new Set(['completed', 'warning', 'error']);
  const isRawTextOnly   = Object.keys(report).length === 1 && typeof report.rawText === 'string';

  // Each element of array fields must be a non-null plain object
  function sanitizeArray(arr) {
    if (!Array.isArray(arr)) return [];
    return arr.filter(item => item !== null && typeof item === 'object' && !Array.isArray(item));
  }

  return {
    // Preserve optional AI-returned fields (vendor, invoice, charts, etc.)
    // Required fields below override any same-named key in the spread.
    ...report,

    schemaVersion:   (typeof report.schemaVersion === 'string' && report.schemaVersion)
                       ? report.schemaVersion : '1.0',

    tool:            (typeof report.tool === 'string' && report.tool)
                       ? report.tool : 'unknown',

    title:           (typeof report.title === 'string' && report.title)
                       ? report.title : 'AI Report',

    status:          isRawTextOnly
                       ? 'error'
                       : VALID_STATUSES.has(report.status) ? report.status : 'completed',

    generatedAt:     (typeof report.generatedAt === 'string' && !isNaN(Date.parse(report.generatedAt)))
                       ? report.generatedAt : new Date().toISOString(),

    summary:         isRawTextOnly
                       ? 'The analysis could not be completed. Please try again.'
                       : (typeof report.summary === 'string' && report.summary)
                           ? report.summary : 'No summary available.',

    metrics:         sanitizeArray(report.metrics),
    findings:        sanitizeArray(report.findings),
    risks:           sanitizeArray(report.risks),
    recommendations: sanitizeArray(report.recommendations),

    confidence: (() => {
      const c = Number(report.confidence);
      return isFinite(c) ? Math.min(100, Math.max(0, c)) : 0;
    })()
  };
}

// ── ANTHROPIC FETCH WITH RETRY ────────────────────────────────────────────────
// Wraps the Anthropic API call with:
//   • 60-second AbortController timeout
//   • Exponential-backoff retry on 429 (rate limit) and 5xx (server error)
//   • No retry on 4xx client errors (400, 401, 403, etc.)
// Returns { ok, status, text } mirroring the fetch Response shape.

async function fetchAnthropicWithRetry(env, payload) {
  const headers = {
    'Content-Type':      'application/json',
    'x-api-key':         env.ANTHROPIC_API_KEY,
    'anthropic-version': '2023-06-01'
  };
  const body = JSON.stringify(payload);

  let lastRes  = null;
  let lastText = '';

  for (let attempt = 0; attempt <= ANTHROPIC_MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), ANTHROPIC_TIMEOUT_MS);

    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', headers, body, signal: controller.signal
      });
      clearTimeout(timer);

      const text = await res.text();

      // Success
      if (res.ok) return { ok: true, status: res.status, text };

      // Client error — do not retry
      if (res.status >= 400 && res.status < 500) {
        return { ok: false, status: res.status, text };
      }

      // Server error or rate limit — retry if attempts remain
      lastRes  = res;
      lastText = text;
      console.warn(`[Anthropic] Attempt ${attempt + 1} failed: ${res.status}`);

      if (attempt < ANTHROPIC_MAX_RETRIES) {
        const delay = ANTHROPIC_RETRY_DELAY * Math.pow(2, attempt);
        await new Promise(r => setTimeout(r, delay));
      }
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        // Surface timeout to caller
        throw err;
      }
      // Network error — retry if attempts remain
      console.warn(`[Anthropic] Attempt ${attempt + 1} network error:`, err.message);
      if (attempt < ANTHROPIC_MAX_RETRIES) {
        const delay = ANTHROPIC_RETRY_DELAY * Math.pow(2, attempt);
        await new Promise(r => setTimeout(r, delay));
      } else {
        throw err;
      }
    }
  }

  return { ok: false, status: lastRes?.status ?? 502, text: lastText };
}

// ── PADDLE HELPERS ────────────────────────────────────────────────────────────

// Verify Paddle Billing v2 HMAC-SHA256 webhook signature.
// Header format: "ts=<unix>; h1=<hex>"  — signed payload: "<ts>:<rawBody>"
async function verifyPaddleSignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;

  const parts = {};
  for (const seg of signatureHeader.split(';')) {
    const eq = seg.indexOf('=');
    if (eq > 0) parts[seg.slice(0, eq).trim()] = seg.slice(eq + 1).trim();
  }
  const { ts, h1 } = parts;
  if (!ts || !h1) return false;

  // Reject webhooks older than 5 minutes — replay-attack prevention
  if (Math.abs(Date.now() / 1000 - parseInt(ts, 10)) > 300) return false;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${ts}:${rawBody}`));
  return safeCompare(bufToHex(sig), h1);
}

async function isPaddleEventProcessed(eventId, env) {
  if (!env.RATE_LIMIT_KV || !eventId) return false;
  try {
    return await env.RATE_LIMIT_KV.get(`${PADDLE_EVENT_KV_PREFIX}${eventId}`) !== null;
  } catch {
    return false;
  }
}

async function markPaddleEventProcessed(eventId, env) {
  if (!env.RATE_LIMIT_KV || !eventId) return;
  try {
    await env.RATE_LIMIT_KV.put(
      `${PADDLE_EVENT_KV_PREFIX}${eventId}`, '1', { expirationTtl: PADDLE_EVENT_TTL_SECONDS }
    );
  } catch {
    console.warn('[Paddle] Failed to mark event processed in KV:', eventId);
  }
}

// Scans the items array for a recognised price ID and returns the plan config.
// Checks every item so multi-price subscriptions are handled correctly.
function resolvePaddlePlan(items) {
  if (!Array.isArray(items)) return null;
  for (const item of items) {
    const cfg = PADDLE_PRICE_PLANS[item?.price?.id];
    if (cfg) return cfg;
  }
  return null;
}

// Creates a Paddle Billing v2 hosted-checkout transaction for the given plan
// and user, and returns the checkout URL the frontend should redirect to.
//
// Uses the Transactions API with `collection_mode: automatic`, which causes
// Paddle to generate a hosted checkout URL at `data.checkout.url` once the
// transaction is created in `draft`/`ready` status. The user's ID is attached
// via custom_data so the webhook handler (subscription.created, etc.) can
// resolve the Wissely account without any extra round trip.
//
// success_url / cancel_url are passed via Paddle's `checkout.url` field as a
// single base return URL — Paddle's hosted checkout appends its own status
// query params to whichever URL is supplied. Since Paddle Billing only
// supports one configured return URL per transaction (not separate success
// and cancel destinations), PADDLE_CHECKOUT_SUCCESS_URL is used as that base
// return URL and the frontend's success.html is responsible for inspecting
// the appended Paddle status/transaction params and redirecting to
// cancel.html if the checkout was not completed. If PADDLE_CHECKOUT_SUCCESS_URL
// is not configured, PADDLE_CHECKOUT_RETURN_URL is used as a fallback so
// existing deployments keep working without a config change.
//
// Returns { ok: true, checkoutUrl } on success, or { ok: false, status, message }
// on any failure — the caller decides how to surface this to the client.
async function createPaddleCheckoutTransaction(env, { priceId, userId, userEmail }) {
  const apiBase = env.PADDLE_API_BASE || 'https://api.paddle.com';

  if (!env.PADDLE_API_KEY) {
    console.error('[Paddle] PADDLE_API_KEY is not configured');
    return { ok: false, status: 500, message: 'Payment provider is not configured' };
  }

  const returnUrl = env.PADDLE_CHECKOUT_SUCCESS_URL || env.PADDLE_CHECKOUT_RETURN_URL || undefined;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PADDLE_CHECKOUT_TIMEOUT_MS);

  try {
    const res = await fetch(`${apiBase}/transactions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.PADDLE_API_KEY}`,
        'Content-Type':  'application/json'
      },
      body: JSON.stringify({
        items: [{ price_id: priceId, quantity: 1 }],
        customer: userEmail ? { email: userEmail } : undefined,
        custom_data: { user_id: userId },
        collection_mode: 'automatic',
        checkout: {
          url: returnUrl
        }
      }),
      signal: controller.signal
    });

    const text = await res.text();

    if (!res.ok) {
      console.error('[Paddle] Transaction creation failed:', res.status, text);
      return { ok: false, status: res.status, message: 'Failed to create checkout transaction' };
    }

    let json;
    try { json = JSON.parse(text); } catch {
      console.error('[Paddle] Transaction response was not valid JSON');
      return { ok: false, status: 502, message: 'Invalid response from payment provider' };
    }

    const checkoutUrl = json?.data?.checkout?.url;
    if (!checkoutUrl) {
      console.error('[Paddle] Transaction created but no checkout URL present:', JSON.stringify(json?.data ?? {}));
      return { ok: false, status: 502, message: 'Checkout URL missing from payment provider response' };
    }

    return { ok: true, checkoutUrl };

  } catch (err) {
    if (err.name === 'AbortError') {
      console.error('[Paddle] Transaction creation timed out');
      return { ok: false, status: 504, message: 'Payment provider timed out' };
    }
    console.error('[Paddle] Transaction creation exception:', err.message);
    return { ok: false, status: 502, message: 'Failed to reach payment provider' };
  } finally {
    clearTimeout(timer);
  }
}

// Fetches a Paddle customer's email address from the Paddle API.
// Used only as a fallback during webhook user resolution, when
// custom_data.user_id was not present on the event payload (e.g. events
// triggered directly from the Paddle dashboard, or older transactions
// created before custom_data was attached).
// Never throws — returns null on any failure so callers can fall back further.
async function fetchPaddleCustomerEmail(env, customerId) {
  if (!customerId || !env.PADDLE_API_KEY) return null;
  const apiBase = env.PADDLE_API_BASE || 'https://api.paddle.com';

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PADDLE_CUSTOMER_LOOKUP_TIMEOUT_MS);

  try {
    const res = await fetch(`${apiBase}/customers/${encodeURIComponent(customerId)}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${env.PADDLE_API_KEY}` },
      signal: controller.signal
    });

    if (!res.ok) {
      console.warn('[Paddle] Customer lookup failed:', res.status, customerId);
      return null;
    }

    const json = await res.json().catch(() => null);
    const email = json?.data?.email;
    return typeof email === 'string' && email ? email : null;

  } catch (err) {
    console.warn('[Paddle] Customer lookup exception:', err.message, customerId);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Resolves the Wissely user ID for an inbound Paddle webhook event.
// Resolution order:
//   1. data.custom_data.user_id — attached at checkout creation, present on
//      almost every event for transactions initiated through Wissely.
//   2. Paddle customer email lookup — fallback for events where custom_data
//      is missing (e.g. manually created subscriptions, dashboard actions),
//      resolved against the local users table by email.
// Returns null if no user can be resolved — callers must handle that case
// without throwing, since Paddle webhooks must always receive a 200.
async function resolveWebhookUserId(env, data) {
  const directUserId = data?.custom_data?.user_id;
  if (directUserId) return directUserId;

  const customerId = data?.customer_id;
  if (!customerId) return null;

  const email = await fetchPaddleCustomerEmail(env, customerId);
  if (!email) return null;

  try {
    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    return user?.id ?? null;
  } catch (err) {
    console.warn('[Paddle] Local user lookup by email failed:', err.message);
    return null;
  }
}

// ── PADDLE EVENT PROCESSOR ────────────────────────────────────────────────────
// Handles all Paddle Billing v2 subscription lifecycle events.
// Always returns — never throws — so the webhook handler can always return 200.

async function processPaddleEvent(eventType, data, env, request, requestId) {
  const subscriptionId = data?.id;
  const customerId     = data?.customer_id;
  // Resolution order: custom_data.user_id first, falling back to a Paddle
  // customer-email lookup against the local users table when absent.
  const userId          = await resolveWebhookUserId(env, data);
  const status         = data?.status ?? 'unknown';
  const planConfig     = resolvePaddlePlan(data?.items);
  const ip             = getClientIp(request);

  const log = (et, meta = {}) =>
    writeAuditLog(env, { requestId, userId, ip, eventType: et, result: 'success', metadata: meta });

  switch (eventType) {

    // ── New subscription created — grant access immediately ──────────────────
    case 'subscription.created': {
      const { plan, analyses_limit } = planConfig ?? PLAN_FREE;
      if (userId) {
        await env.DB.prepare(
          'UPDATE users SET plan = ?, analyses_limit = ?, paddle_customer_id = ?, ' +
          'paddle_subscription_id = ?, subscription_status = ? WHERE id = ?'
        ).bind(plan, analyses_limit, customerId, subscriptionId, status, userId).run();
      } else if (customerId) {
        await env.DB.prepare(
          'UPDATE users SET plan = ?, analyses_limit = ?, paddle_subscription_id = ?, ' +
          'subscription_status = ? WHERE paddle_customer_id = ?'
        ).bind(plan, analyses_limit, subscriptionId, status, customerId).run();
      } else {
        console.warn('[Paddle] subscription.created — no resolvable user, skipped');
      }
      await log('paddle_subscription_created', { plan, subscriptionId });
      break;
    }

    // ── Trial-to-paid conversion — apply billing plan at payment time ────────
    case 'subscription.activated': {
      const { plan, analyses_limit } = planConfig ?? PLAN_FREE;
      await env.DB.prepare(
        'UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? ' +
        'WHERE paddle_subscription_id = ?'
      ).bind(plan, analyses_limit, status, subscriptionId).run();
      await log('paddle_subscription_activated', { plan, subscriptionId });
      break;
    }

    // ── Plan change or renewal — reconfirm plan and quota ───────────────────
    // Quota resets happen in the monthly cron, not here.
    case 'subscription.updated': {
      const { plan, analyses_limit } = planConfig ?? PLAN_FREE;
      if (userId) {
        await env.DB.prepare(
          'UPDATE users SET plan = ?, analyses_limit = ?, paddle_customer_id = ?, ' +
          'paddle_subscription_id = ?, subscription_status = ? WHERE id = ?'
        ).bind(plan, analyses_limit, customerId, subscriptionId, status, userId).run();
      } else if (subscriptionId) {
        await env.DB.prepare(
          'UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? ' +
          'WHERE paddle_subscription_id = ?'
        ).bind(plan, analyses_limit, status, subscriptionId).run();
      } else {
        console.warn('[Paddle] subscription.updated — no resolvable user, skipped');
      }
      await log('paddle_subscription_updated', { plan, status, subscriptionId });
      break;
    }

    // ── Cancellation — revert to free tier immediately ───────────────────────
    case 'subscription.canceled': {
      await env.DB.prepare(
        'UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? ' +
        'WHERE paddle_subscription_id = ?'
      ).bind(PLAN_FREE.plan, PLAN_FREE.analyses_limit, 'canceled', subscriptionId).run();
      await log('paddle_subscription_canceled', { subscriptionId });
      break;
    }

    // ── Billing paused (dunning exhausted) — revert to free tier ────────────
    case 'subscription.paused': {
      await env.DB.prepare(
        'UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? ' +
        'WHERE paddle_subscription_id = ?'
      ).bind(PLAN_FREE.plan, PLAN_FREE.analyses_limit, 'paused', subscriptionId).run();
      await log('paddle_subscription_paused', { subscriptionId });
      break;
    }

    // ── Subscription reactivated from pause — restore plan ───────────────────
    case 'subscription.resumed': {
      const { plan, analyses_limit } = planConfig ?? PLAN_FREE;
      await env.DB.prepare(
        'UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? ' +
        'WHERE paddle_subscription_id = ?'
      ).bind(plan, analyses_limit, status, subscriptionId).run();
      await log('paddle_subscription_resumed', { plan, subscriptionId });
      break;
    }

    // ── Paddle-managed trial — update status flag only ───────────────────────
    // Do not alter analyses_limit — that is set when the trial converts.
    case 'subscription.trialing': {
      await env.DB.prepare(
        'UPDATE users SET subscription_status = ? WHERE paddle_subscription_id = ?'
      ).bind('trialing', subscriptionId).run();
      break;
    }

    // ── Payment past due — flag only; do not strip access yet ────────────────
    // Access is stripped when subscription.paused or subscription.canceled fires.
    case 'subscription.past_due': {
      await env.DB.prepare(
        'UPDATE users SET subscription_status = ? WHERE paddle_subscription_id = ?'
      ).bind('past_due', subscriptionId).run();
      await writeAuditLog(env, {
        requestId, userId, ip, eventType: 'paddle_subscription_past_due',
        result: 'warning', metadata: { subscriptionId }
      });
      break;
    }

    // ── Successful payment — secondary safety-net confirmation ───────────────
    // subscription.updated fires for renewals too; this event provides a hard
    // confirmation of active status after every real payment.
    case 'transaction.completed': {
      const txnSubId     = data?.subscription_id;
      const txnPlanConf  = resolvePaddlePlan(data?.items);
      if (txnSubId && txnPlanConf) {
        const { plan, analyses_limit } = txnPlanConf;
        await env.DB.prepare(
          "UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = 'active' " +
          'WHERE paddle_subscription_id = ?'
        ).bind(plan, analyses_limit, txnSubId).run();
        await log('paddle_transaction_completed', { plan, subscriptionId: txnSubId });
      }
      break;
    }

    // ── Payment failed — log for monitoring; Paddle handles dunning ──────────
    case 'transaction.payment_failed': {
      const txnSubId = data?.subscription_id;
      if (txnSubId) {
        console.warn('[Paddle] Payment failed for subscription:', txnSubId);
        await writeAuditLog(env, {
          requestId, ip, eventType: 'paddle_payment_failed',
          result: 'warning', metadata: { subscriptionId: txnSubId }
        });
      }
      break;
    }

    default:
      console.log(`[Paddle] Unhandled event type ignored: ${eventType}`);
  }
}

// ── PADDLE CUSTOMER PORTAL ────────────────────────────────────────────────────
// Creates a Paddle Billing v2 Customer Portal session for the given customer
// and returns the URL the frontend should redirect the user to.
//
// Paddle's Customer Portal allows subscribers to view invoices, update payment
// methods, and manage or cancel their own subscription — replacing any need for
// a bespoke cancel/manage flow on the Wissely side.
//
// API reference:
//   POST /customers/{customer_id}/portal-sessions
//   Response: { data: { urls: { customer_portal: "https://..." } } }
//
// The portal session URL is single-use and expires after a short window (Paddle
// enforces this server-side). No URL should be cached or reused across requests.
//
// Returns { ok: true, portalUrl } on success, or { ok: false, status, message }
// on any failure — the caller decides how to surface the error to the client.

async function createPaddlePortalSession(env, customerId) {
  if (!customerId) {
    return { ok: false, status: 400, message: 'No billing account found. Please contact support.' };
  }

  if (!env.PADDLE_API_KEY) {
    console.error('[Paddle] PADDLE_API_KEY is not configured');
    return { ok: false, status: 500, message: 'Payment provider is not configured' };
  }

  const apiBase = env.PADDLE_API_BASE || 'https://api.paddle.com';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PADDLE_PORTAL_TIMEOUT_MS);

  try {
    const res = await fetch(
      `${apiBase}/customers/${encodeURIComponent(customerId)}/portal-sessions`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.PADDLE_API_KEY}`,
          'Content-Type':  'application/json'
        },
        // Empty body — Paddle generates a full-access portal session by default.
        // Optionally accepts { subscription_ids: [...] } to scope the session.
        body: JSON.stringify({}),
        signal: controller.signal
      }
    );

    const text = await res.text();

    if (!res.ok) {
      console.error('[Paddle] Portal session creation failed:', res.status, text);
      return { ok: false, status: res.status, message: 'Failed to create billing portal session' };
    }

    let json;
    try { json = JSON.parse(text); } catch {
      console.error('[Paddle] Portal session response was not valid JSON');
      return { ok: false, status: 502, message: 'Invalid response from payment provider' };
    }

    const portalUrl = json?.data?.urls?.customer_portal;
    if (!portalUrl) {
      console.error('[Paddle] Portal session created but no URL present:', JSON.stringify(json?.data ?? {}));
      return { ok: false, status: 502, message: 'Billing portal URL missing from payment provider response' };
    }

    return { ok: true, portalUrl };

  } catch (err) {
    if (err.name === 'AbortError') {
      console.error('[Paddle] Portal session creation timed out');
      return { ok: false, status: 504, message: 'Payment provider timed out' };
    }
    console.error('[Paddle] Portal session creation exception:', err.message);
    return { ok: false, status: 502, message: 'Failed to reach payment provider' };
  } finally {
    clearTimeout(timer);
  }
}

// ── STALE-DATA CLEANUP ────────────────────────────────────────────────────────
// Runs on ~5 % of all requests via waitUntil() — no impact on response latency.
// Deletes expired sessions, reset tokens, and verification tokens in one batch.

async function runInlineCleanup(env) {
  const now = new Date().toISOString();
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
      env.DB.prepare('DELETE FROM password_resets WHERE expires_at < ?').bind(now),
      env.DB.prepare(
        'UPDATE users SET email_verification_token = NULL, email_verification_expires = NULL ' +
        'WHERE email_verified = 0 AND email_verification_expires IS NOT NULL ' +
        'AND email_verification_expires < ?'
      ).bind(now)
    ]);
  } catch (err) {
    console.warn('[Cleanup] Inline stale-data cleanup failed:', err.message);
  }
}

// ── MAIN FETCH HANDLER ────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url);
    const path = url.pathname;

    // Unique request ID propagated through every log line for correlation
    const requestId = crypto.randomUUID();

    // ── CORS preflight ────────────────────────────────────────────────────────
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin':      getAllowedOrigin(request),
          'Access-Control-Allow-Methods':     'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers':     'Content-Type, Authorization, X-CSRF-Token',
          'Access-Control-Allow-Credentials': 'true',
          'Access-Control-Max-Age':           '86400',
          'Vary':                             'Origin',
          ...SECURITY_HEADERS
        }
      });
    }

    try {
      // Probabilistic inline cleanup — fires on ~5 % of requests, never blocks
      if (Math.random() < 0.05) {
        ctx.waitUntil(runInlineCleanup(env));
      }

      // ── HEALTH ────────────────────────────────────────────────────────────
      if (path === '/health' && request.method === 'GET') {
        let dbStatus = 'ok';
        try { await env.DB.prepare('SELECT 1').first(); }
        catch { dbStatus = 'error'; }

        const healthy = dbStatus === 'ok';
        return createResponse(request, {
          status:    healthy ? 'ok' : 'degraded',
          version:   '1.0.0',
          timestamp: new Date().toISOString(),
          services:  { db: dbStatus }
        }, healthy ? 200 : 503);
      }

      // ── PADDLE WEBHOOK ────────────────────────────────────────────────────
      if (path === '/webhook/paddle' && request.method === 'POST') {
        // Raw body must be captured before any other parsing — the HMAC is
        // computed over the exact bytes received, not a re-serialised object.
        const rawBody         = await request.text();
        const signatureHeader = request.headers.get('Paddle-Signature');
        const ip              = getClientIp(request);

        // Step 1 — Verify HMAC-SHA256 signature and replay window
        const isValid = await verifyPaddleSignature(
          env.PADDLE_WEBHOOK_SECRET, rawBody, signatureHeader
        );
        if (!isValid) {
          console.warn('[Paddle] Webhook signature invalid', { requestId, ip });
          await writeAuditLog(env, {
            requestId, ip,
            eventType: 'paddle_webhook_signature_invalid',
            result:    'failure'
          });
          // Track for security monitoring — alert on repeated failures from one IP
          await trackSecurityFailure(env, request, {
            kvPrefix:        'webhook_sig_fail',
            windowSeconds:   WEBHOOK_FAIL_WINDOW_SECONDS,
            threshold:       WEBHOOK_FAIL_ALERT_THRESHOLD,
            alertEventType:  'paddle_webhook_signature_repeated_failure',
            requestId
          });
          // 400 — Paddle treats 4xx as permanent failure and does not retry
          return createResponse(request, { error: 'Invalid webhook signature' }, 400);
        }

        // Step 2 — Parse payload
        let event;
        try { event = JSON.parse(rawBody); }
        catch { return createResponse(request, { error: 'Invalid JSON payload' }, 400); }

        const { event_id: eventId, event_type: eventType, data } = event;

        // Step 3 — Idempotency check (Paddle retries on non-2xx with backoff)
        if (await isPaddleEventProcessed(eventId, env)) {
          console.log(`[Paddle] Duplicate event ignored: ${eventId} (${eventType})`);
          return createResponse(request, { received: true, duplicate: true }, 200);
        }

        // Step 4 — Process
        try {
          await processPaddleEvent(eventType, data, env, request, requestId);
        } catch (err) {
          // Log but always return 200 — Paddle must not retry internal failures.
          // Event intentionally NOT marked processed so a dashboard re-delivery works.
          console.error('[Paddle] processPaddleEvent threw:', err.message, { requestId, eventType, eventId });
          await writeAuditLog(env, {
            requestId, ip,
            eventType: 'paddle_webhook_processing_error',
            result:    'failure',
            metadata:  { eventType, eventId, error: err.message }
          });
          return createResponse(request, { received: true }, 200);
        }

        // Step 5 — Mark processed (non-blocking)
        ctx.waitUntil(markPaddleEventProcessed(eventId, env));
        console.log(`[Paddle] Event processed: ${eventId} (${eventType})`, { requestId });
        return createResponse(request, { received: true }, 200);
      }

      // ── REGISTER ──────────────────────────────────────────────────────────
      if (path === '/register' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'register')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email, password } = body ?? {};
        if (!email || !password) {
          return createResponse(request, { error: 'Email and password required' }, 400);
        }
        if (email.length    > MAX_EMAIL_LENGTH)    return createResponse(request, { error: 'Email address is too long' }, 400);
        if (password.length > MAX_PASSWORD_LENGTH) return createResponse(request, { error: 'Password is too long' }, 400);
        if (password.length < 8)                   return createResponse(request, { error: 'Password must be at least 8 characters' }, 400);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return createResponse(request, { error: 'Invalid email address' }, 400);
        }

        const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (existing) return createResponse(request, { error: 'Email already registered' }, 409);

        const userId       = crypto.randomUUID();
        const { hash, salt } = await hashPassword(password);
        const trialEnd     = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();
        const now          = new Date().toISOString();

        const rawVerifyToken    = generateSecureToken();
        const hashedVerifyToken = await hashToken(rawVerifyToken);
        const verifyExpires     = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        await env.DB.prepare(
          'INSERT INTO users (id, email, password_hash, password_salt, plan, analyses_used, analyses_limit, ' +
          'trial_end, created_at, email_verified, email_verification_token, email_verification_expires) ' +
          'VALUES (?, ?, ?, ?, ?, 0, 20, ?, ?, 0, ?, ?)'
        ).bind(userId, email, hash, salt, 'trial', trialEnd, now, hashedVerifyToken, verifyExpires).run();

        await writeAuditLog(env, {
          requestId, userId, ip: getClientIp(request),
          eventType: 'register', result: 'success'
        });

        const verifyLink = `https://app.wissely.com/verify-email.html?token=${rawVerifyToken}`;
        ctx.waitUntil(sendEmailWithRetry(env, {
          to:      email,
          subject: 'Verify your Wissely email address',
          html:    buildVerificationEmailHtml(verifyLink, false),
          text:    `Verify your Wissely email address: ${verifyLink}`,
          logTag:  'Register'
        }));

        return createResponse(request, {
          success:              true,
          message:              'Account created. Please check your email to verify your account.',
          requiresVerification: true
        }, 201);
      }

      // ── LOGIN ─────────────────────────────────────────────────────────────
      if (path === '/login' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'login')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email, password } = body ?? {};
        if (!email || !password) return createResponse(request, { error: 'Fields required' }, 400);
        if (email.length > MAX_EMAIL_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
          return createResponse(request, { error: 'Invalid email or password' }, 401);
        }

        const ip = getClientIp(request);

        // Brute-force block — checked before any DB work
        if (await checkLoginBlock(request, env, email)) {
          await writeAuditLog(env, {
            requestId, ip, eventType: 'login_blocked', result: 'failure',
            metadata: { email: email.slice(0, 3) + '***' }
          });
          return createResponse(request, { error: 'Too many failed login attempts. Please try again later.' }, 429);
        }

        const user = await env.DB.prepare(
          'SELECT id, email, password_hash, password_salt, plan, analyses_used, analyses_limit, email_verified ' +
          'FROM users WHERE email = ?'
        ).bind(email).first();

        if (!user) {
          // Dummy hash to equalise timing regardless of whether the user exists
          await hashPassword(password);
          await recordLoginFailure(request, env, email);
          await writeAuditLog(env, {
            requestId, ip, eventType: 'login_failed', result: 'failure',
            metadata: { reason: 'user_not_found' }
          });
          return createResponse(request, { error: 'Invalid email or password' }, 401);
        }

        const { hash } = await hashPassword(password, user.password_salt);
        if (!safeCompare(hash, user.password_hash)) {
          await recordLoginFailure(request, env, email);
          await writeAuditLog(env, {
            requestId, userId: user.id, ip, eventType: 'login_failed', result: 'failure',
            metadata: { reason: 'invalid_password' }
          });
          return createResponse(request, { error: 'Invalid email or password' }, 401);
        }

        if (!user.email_verified) {
          return createResponse(request, {
            error:                'Please verify your email address before logging in.',
            requiresVerification: true
          }, 403);
        }

        // Successful authentication
        await clearLoginFailures(request, env, email);

        const rawSessionId  = generateSecureToken();
        const sessionHash   = await hashToken(rawSessionId); // only the hash goes to DB
        const csrfToken     = generateSecureToken();
        const expiresAt     = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        // Atomic: invalidate all previous sessions and create the new one
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
          env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at, csrf_token) VALUES (?, ?, ?, ?)')
            .bind(sessionHash, user.id, expiresAt.toISOString(), csrfToken)
        ]);

        await writeAuditLog(env, {
          requestId, userId: user.id, ip, eventType: 'login_success', result: 'success'
        });

        const cookieStr = [
          `wissely_session=${rawSessionId}`,
          `Expires=${expiresAt.toUTCString()}`,
          'HttpOnly',
          'Path=/',
          'SameSite=None',
          'Secure'
        ].join('; ');

        return createResponse(request, {
          success:   true,
          csrfToken, // stored by frontend, sent as X-CSRF-Token on subsequent requests
          user: {
            id:              user.id,
            email:           user.email,
            plan:            user.plan,
            analyses_used:   user.analyses_used,
            analyses_limit:  user.analyses_limit
          }
        }, 200, { 'Set-Cookie': cookieStr });
      }

      // ── VERIFY EMAIL ──────────────────────────────────────────────────────
      if (path === '/verify-email' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'verify-email')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { token } = body ?? {};
        if (!token)                        return createResponse(request, { error: 'Verification token required' }, 400);
        if (token.length > MAX_TOKEN_LENGTH) return createResponse(request, { error: 'Invalid verification token' }, 400);

        const hashedToken = await hashToken(token);
        const ip          = getClientIp(request);

        const targetUser = await env.DB.prepare(
          'SELECT id, email_verification_expires FROM users ' +
          'WHERE email_verification_token = ? AND email_verified = 0'
        ).bind(hashedToken).first();

        if (!targetUser) {
          await writeAuditLog(env, {
            requestId, ip, eventType: 'email_verification_failed', result: 'failure',
            metadata: { reason: 'invalid_token' }
          });
          return createResponse(request, { error: 'Invalid or already used verification link.' }, 400);
        }

        if (Date.now() > new Date(targetUser.email_verification_expires).getTime()) {
          await writeAuditLog(env, {
            requestId, userId: targetUser.id, ip,
            eventType: 'email_verification_failed', result: 'failure',
            metadata: { reason: 'token_expired' }
          });
          return createResponse(request, { error: 'Verification link has expired. Please request a new one.' }, 400);
        }

        await env.DB.prepare(
          'UPDATE users SET email_verified = 1, email_verification_token = NULL, ' +
          'email_verification_expires = NULL WHERE id = ?'
        ).bind(targetUser.id).run();

        await writeAuditLog(env, {
          requestId, userId: targetUser.id, ip, eventType: 'email_verified', result: 'success'
        });

        return createResponse(request, {
          success: true,
          message: 'Email verified successfully. You can now log in.'
        }, 200);
      }

      // ── FORGOT PASSWORD ───────────────────────────────────────────────────
      if (path === '/forgot-password' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'forgot-password')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email } = body ?? {};
        if (!email) return createResponse(request, { error: 'Email required' }, 400);

        // Enumeration-safe: always return the same response
        const safeResponse = createResponse(request, {
          success: true,
          message: 'If the provided account exists, a reset link has been sent.'
        }, 200);

        if (email.length > MAX_EMAIL_LENGTH) return safeResponse;

        const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (!user) return safeResponse;

        const rawToken    = generateSecureToken();
        const hashedToken = await hashToken(rawToken);
        const expiresAt   = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
        const createdAt   = new Date().toISOString();

        // Atomic: delete any outstanding token then insert the new one
        await env.DB.batch([
          env.DB.prepare('DELETE FROM password_resets WHERE user_id = ?').bind(user.id),
          env.DB.prepare(
            'INSERT INTO password_resets (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
          ).bind(hashedToken, user.id, expiresAt, createdAt)
        ]);

        await writeAuditLog(env, {
          requestId, userId: user.id, ip: getClientIp(request),
          eventType: 'password_reset_requested', result: 'success'
        });

        const resetLink = `https://app.wissely.com/reset-password.html?token=${rawToken}`;
        ctx.waitUntil(sendEmailWithRetry(env, {
          to:      email,
          subject: 'Reset your Wissely password',
          html:    buildPasswordResetEmailHtml(resetLink),
          text:    `Reset your password: ${resetLink}`,
          logTag:  'ForgotPassword'
        }));

        return safeResponse;
      }

      // ── RESET PASSWORD ────────────────────────────────────────────────────
      if (path === '/reset-password' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'reset-password')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { token, password } = body ?? {};
        if (!token || !password) return createResponse(request, { error: 'Token and password are required' }, 400);
        if (token.length    > MAX_TOKEN_LENGTH)    return createResponse(request, { error: 'Invalid reset token' }, 400);
        if (password.length > MAX_PASSWORD_LENGTH) return createResponse(request, { error: 'Password is too long' }, 400);
        if (password.length < 8)                   return createResponse(request, { error: 'Password must be at least 8 characters' }, 400);

        const hashedToken = await hashToken(token);
        const ip          = getClientIp(request);

        const resetRecord = await env.DB.prepare(
          'SELECT token, user_id, expires_at FROM password_resets WHERE token = ?'
        ).bind(hashedToken).first();

        if (!resetRecord) {
          await writeAuditLog(env, {
            requestId, ip, eventType: 'password_reset_failed', result: 'failure',
            metadata: { reason: 'invalid_token' }
          });
          return createResponse(request, { error: 'Invalid or expired reset link' }, 400);
        }

        if (Date.now() > new Date(resetRecord.expires_at).getTime()) {
          await env.DB.prepare('DELETE FROM password_resets WHERE token = ?').bind(hashedToken).run();
          await writeAuditLog(env, {
            requestId, userId: resetRecord.user_id, ip,
            eventType: 'password_reset_failed', result: 'failure',
            metadata: { reason: 'token_expired' }
          });
          return createResponse(request, { error: 'Reset link has expired. Please request a new one.' }, 400);
        }

        const { hash, salt } = await hashPassword(password);

        // Atomic: update password, nuke all sessions, delete reset token
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
            .bind(hash, salt, resetRecord.user_id),
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(resetRecord.user_id),
          env.DB.prepare('DELETE FROM password_resets WHERE user_id = ?').bind(resetRecord.user_id)
        ]);

        await writeAuditLog(env, {
          requestId, userId: resetRecord.user_id, ip,
          eventType: 'password_reset_success', result: 'success'
        });

        return createResponse(request, {
          success: true,
          message: 'Password updated successfully. Please log in with your new password.'
        }, 200);
      }

      // ── ME ────────────────────────────────────────────────────────────────
      if (path === '/me' && request.method === 'GET') {
        const session = await authenticateSession(request, env);
        if (!session) return createResponse(request, { error: 'Unauthenticated' }, 401);

        const userPayload = {
          id:             session.user_id,
          email:          session.email,
          plan:           session.plan,
          analyses_used:  session.analyses_used,
          analyses_limit: session.analyses_limit,
          trial_end:      session.trial_end
        };

        if (session.isExpiredTrial) {
          return createResponse(request, {
            authenticated: true,
            trialExpired:  true,
            user:          userPayload
          }, 403);
        }

        return createResponse(request, { authenticated: true, user: userPayload });
      }

      // ── LOGOUT ────────────────────────────────────────────────────────────
      if (path === '/logout' && request.method === 'POST') {
        const csrfValid = await validateCsrfToken(request, env, requestId);
        if (!csrfValid) {
          await writeAuditLog(env, {
            requestId, ip: getClientIp(request),
            eventType: 'csrf_validation_failed', result: 'failure',
            metadata: { path: '/logout' }
          });
          await trackSecurityFailure(env, request, {
            kvPrefix:       'csrf_fail',
            windowSeconds:  CSRF_FAIL_WINDOW_SECONDS,
            threshold:      CSRF_FAIL_ALERT_THRESHOLD,
            alertEventType: 'csrf_repeated_failure',
            requestId
          });
          return createResponse(request, { error: 'Invalid or missing security token' }, 403);
        }

        const cookies   = parseCookies(request);
        const rawId     = cookies['wissely_session'];
        let   userId    = null;

        if (rawId) {
          const sessionHash = await hashToken(rawId);
          const row = await env.DB.prepare('SELECT user_id FROM sessions WHERE id = ?')
            .bind(sessionHash).first();
          if (row) userId = row.user_id;
          await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionHash).run();
        }

        await writeAuditLog(env, {
          requestId, userId, ip: getClientIp(request), eventType: 'logout', result: 'success'
        });

        return createResponse(request, { success: true }, 200, {
          'Set-Cookie': 'wissely_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure'
        });
      }

      // ── CREATE CHECKOUT ───────────────────────────────────────────────────
      // Creates a Paddle Billing v2 hosted-checkout transaction for the
      // requested plan and returns the URL the frontend should redirect to.
      // No price IDs or Paddle credentials are exposed to the client at any
      // point — the price ID is resolved server-side from PLAN_TO_PRICE_ID,
      // which is itself derived from the existing PADDLE_PRICE_PLANS map.
      if (path === '/create-checkout' && request.method === 'POST') {
        const session = await authenticateSession(request, env);
        if (!session)               return createResponse(request, { error: 'Unauthorized' }, 401);
        if (session.isExpiredTrial) return createResponse(request, { error: 'Trial expired' }, 403);

        const csrfValid = await validateCsrfToken(request, env, requestId);
        if (!csrfValid) {
          await writeAuditLog(env, {
            requestId, userId: session.user_id, ip: getClientIp(request),
            eventType: 'csrf_validation_failed', result: 'failure',
            metadata: { path: '/create-checkout' }
          });
          await trackSecurityFailure(env, request, {
            kvPrefix:       'csrf_fail',
            windowSeconds:  CSRF_FAIL_WINDOW_SECONDS,
            threshold:      CSRF_FAIL_ALERT_THRESHOLD,
            alertEventType: 'csrf_repeated_failure',
            requestId
          });
          return createResponse(request, { error: 'Invalid or missing security token' }, 403);
        }

        if (await checkRateLimit(request, env, 'create-checkout')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { plan } = body ?? {};
        const priceId   = typeof plan === 'string' ? PLAN_TO_PRICE_ID[plan] : undefined;

        if (!priceId) {
          return createResponse(request, {
            error: 'Invalid plan. Allowed values are: starter, growth, pro.'
          }, 400);
        }

        // Block redundant checkouts — a user already on the requested plan
        // (with an active/trialing subscription) gains nothing from a new
        // transaction and Paddle would simply create a duplicate subscription.
        if (session.plan === plan) {
          return createResponse(request, {
            error: `You are already subscribed to the ${plan} plan.`
          }, 409);
        }

        const ip = getClientIp(request);

        const result = await createPaddleCheckoutTransaction(env, {
          priceId,
          userId:    session.user_id,
          userEmail: session.email
        });

        if (!result.ok) {
          await writeAuditLog(env, {
            requestId, userId: session.user_id, ip,
            eventType: 'checkout_creation_failed', result: 'failure',
            metadata: { plan, status: result.status }
          });
          return createResponse(request, {
            error: result.message || 'Unable to create checkout session. Please try again.'
          }, result.status && result.status >= 400 && result.status < 600 ? result.status : 502);
        }

        await writeAuditLog(env, {
          requestId, userId: session.user_id, ip,
          eventType: 'checkout_created', result: 'success',
          metadata: { plan }
        });

        return createResponse(request, { checkoutUrl: result.checkoutUrl }, 200);
      }

      // ── ANALYZE ───────────────────────────────────────────────────────────
      if (path === '/analyze' && request.method === 'POST') {
        const session = await authenticateSession(request, env);
        if (!session)                return createResponse(request, { error: 'Unauthorized' }, 401);
        if (session.isExpiredTrial)  return createResponse(request, { error: 'Trial expired' }, 403);

        const csrfValid = await validateCsrfToken(request, env, requestId);
        if (!csrfValid) {
          await writeAuditLog(env, {
            requestId, userId: session.user_id, ip: getClientIp(request),
            eventType: 'csrf_validation_failed', result: 'failure',
            metadata: { path: '/analyze' }
          });
          await trackSecurityFailure(env, request, {
            kvPrefix:       'csrf_fail',
            windowSeconds:  CSRF_FAIL_WINDOW_SECONDS,
            threshold:      CSRF_FAIL_ALERT_THRESHOLD,
            alertEventType: 'csrf_repeated_failure',
            requestId
          });
          return createResponse(request, { error: 'Invalid or missing security token' }, 403);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);
        if (!body?.messages) return createResponse(request, { error: 'Missing messages field' }, 400);

        // Payload size gate — checked before quota is consumed
        const payloadBytes = new TextEncoder().encode(JSON.stringify(body.messages)).length;
        if (payloadBytes > MAX_AI_PAYLOAD_BYTES) {
          console.warn('[Analyze] Payload too large:', payloadBytes, 'bytes, user:', session.user_id, { requestId });
          return createResponse(request, {
            error: 'Payload too large. Please reduce the size of your input and try again.'
          }, 413);
        }

        // Atomic quota gate — single UPDATE prevents over-consumption under concurrent requests
        const allocation = await env.DB.prepare(
          'UPDATE users SET analyses_used = analyses_used + 1 ' +
          'WHERE id = ? AND analyses_used < analyses_limit'
        ).bind(session.user_id).run();

        if (allocation.meta.changes === 0) {
          return createResponse(request, { error: 'Usage limit reached for this month' }, 403);
        }

        // Quota has been consumed — roll back on any downstream failure
        try {
          const result = await fetchAnthropicWithRetry(env, {
            model:     'claude-sonnet-4-6',
            max_tokens: 1000,
            system:    buildSystemPrompt(body.tool || 'unknown'),
            messages:  body.messages
          });

          if (result.ok) {
            const updatedUser = await env.DB.prepare(
              'SELECT id, email, plan, analyses_used, analyses_limit, trial_end FROM users WHERE id = ?'
            ).bind(session.user_id).first();

            const report = validateAIReport(extractAIReport(result.text));

            await writeAuditLog(env, {
              requestId,
              userId:    session.user_id,
              ip:        getClientIp(request),
              eventType: 'analysis_completed',
              result:    'success',
              metadata:  { tool: body.tool || 'unknown' }
            });

            return createResponse(request, { success: true, data: report, user: updatedUser });
          }

          // Non-OK Anthropic response — roll back
          await env.DB.prepare('UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?')
            .bind(session.user_id).run();
          console.error('[Analyze] Anthropic non-OK:', result.status, { requestId });
          return createResponse(request, { error: 'Analysis service unavailable. Please try again.' }, 502);

        } catch (apiError) {
          // Roll back quota on timeout or network failure
          await env.DB.prepare('UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?')
            .bind(session.user_id).run();

          if (apiError.name === 'AbortError') {
            console.warn('[Analyze] Anthropic timed out', { requestId, userId: session.user_id });
            return createResponse(request, { error: 'Analysis timed out. Please try again.' }, 504);
          }

          console.error('[Analyze] Upstream fetch failed:', apiError.message, { requestId });
          throw apiError;
        }
      }

      // ── RESEND VERIFICATION ───────────────────────────────────────────────
      if (path === '/resend-verification' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'resend-verification')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email } = body ?? {};
        if (!email) return createResponse(request, { error: 'Email required' }, 400);

        // Enumeration-safe response — always returned
        const safeResponse = createResponse(request, {
          success: true,
          message: 'If the account exists and is not yet verified, a new verification email has been sent.'
        }, 200);

        if (email.length > MAX_EMAIL_LENGTH) return safeResponse;

        const user = await env.DB.prepare(
          'SELECT id, email_verified FROM users WHERE email = ?'
        ).bind(email).first();

        if (user && !user.email_verified) {
          const rawToken      = generateSecureToken();
          const hashedToken   = await hashToken(rawToken);
          const verifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

          await env.DB.prepare(
            'UPDATE users SET email_verification_token = ?, email_verification_expires = ? WHERE id = ?'
          ).bind(hashedToken, verifyExpires, user.id).run();

          const verifyLink = `https://app.wissely.com/verify-email.html?token=${rawToken}`;
          ctx.waitUntil(sendEmailWithRetry(env, {
            to:      email,
            subject: 'Verify your Wissely email address',
            html:    buildVerificationEmailHtml(verifyLink, true),
            text:    `Verify your Wissely email address: ${verifyLink}`,
            logTag:  'ResendVerification'
          }));
        }

        return safeResponse;
      }

      // ── BILLING PORTAL ────────────────────────────────────────────────────
      // Creates a Paddle Customer Portal session for the authenticated user
      // and returns the single-use portal URL for the frontend to redirect to.
      // The portal lets subscribers manage payment methods, view invoices, and
      // cancel or change their subscription without any additional Wissely UI.
      if (path === '/billing-portal' && request.method === 'POST') {
        const session = await authenticateSession(request, env);
        if (!session)               return createResponse(request, { error: 'Unauthorized' }, 401);
        if (session.isExpiredTrial) return createResponse(request, { error: 'Trial expired' }, 403);

        const csrfValid = await validateCsrfToken(request, env, requestId);
        if (!csrfValid) {
          await writeAuditLog(env, {
            requestId, userId: session.user_id, ip: getClientIp(request),
            eventType: 'csrf_validation_failed', result: 'failure',
            metadata: { path: '/billing-portal' }
          });
          await trackSecurityFailure(env, request, {
            kvPrefix:       'csrf_fail',
            windowSeconds:  CSRF_FAIL_WINDOW_SECONDS,
            threshold:      CSRF_FAIL_ALERT_THRESHOLD,
            alertEventType: 'csrf_repeated_failure',
            requestId
          });
          return createResponse(request, { error: 'Invalid or missing security token' }, 403);
        }

        if (await checkRateLimit(request, env, 'billing-portal')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const ip = getClientIp(request);

        // Retrieve the Paddle customer ID stored when the subscription was
        // first created. It is not included in the session object, so a
        // targeted DB read is required.
        let customerId = null;
        try {
          const row = await env.DB.prepare(
            'SELECT paddle_customer_id FROM users WHERE id = ?'
          ).bind(session.user_id).first();
          customerId = row?.paddle_customer_id ?? null;
        } catch (err) {
          console.error('[BillingPortal] DB lookup failed:', err.message, { requestId });
          return createResponse(request, {
            error: 'Unable to retrieve billing account. Please try again.'
          }, 502);
        }

        if (!customerId) {
          // User has never completed a Paddle checkout — no portal session exists.
          await writeAuditLog(env, {
            requestId, userId: session.user_id, ip,
            eventType: 'billing_portal_no_customer', result: 'failure',
            metadata: { plan: session.plan }
          });
          return createResponse(request, {
            error: 'No billing account found. Please subscribe to a plan first.'
          }, 404);
        }

        const result = await createPaddlePortalSession(env, customerId);

        if (!result.ok) {
          await writeAuditLog(env, {
            requestId, userId: session.user_id, ip,
            eventType: 'billing_portal_failed', result: 'failure',
            metadata: { status: result.status }
          });
          return createResponse(request, {
            error: result.message || 'Unable to open billing portal. Please try again.'
          }, result.status && result.status >= 400 && result.status < 600 ? result.status : 502);
        }

        await writeAuditLog(env, {
          requestId, userId: session.user_id, ip,
          eventType: 'billing_portal_opened', result: 'success'
        });

        return createResponse(request, { portalUrl: result.portalUrl }, 200);
      }

      return createResponse(request, { error: 'Not found' }, 404);

    } catch (globalError) {
      // Internal implementation details must never reach the client
      console.error('[Worker] Unhandled exception:', globalError.message, {
        requestId, path, method: request.method
      });
      return createResponse(request, { error: 'An unexpected error occurred' }, 500);
    }
  },

  // ── CRON: Monthly maintenance ─────────────────────────────────────────────
  // Schedule: "0 0 1 * *"  (00:00 UTC on the 1st of every month)
  // The UTC date guard is a safety net against misconfigured trigger schedules.
  async scheduled(event, env, ctx) {
    const today = new Date();
    if (today.getUTCDate() !== 1) {
      console.log('[Cron] Monthly maintenance skipped — not the 1st (UTC)');
      return;
    }

    console.log('[Cron] Monthly maintenance starting');
    const now = new Date().toISOString();

    // ── Reset all usage counters ─────────────────────────────────────────────
    try {
      const r = await env.DB.prepare('UPDATE users SET analyses_used = 0').run();
      console.log(`[Cron] Usage reset: ${r.meta.changes} user(s)`);
    } catch (err) { console.error('[Cron] Usage reset failed:', err.message); }

    // ── Delete expired password reset tokens ─────────────────────────────────
    try {
      const r = await env.DB.prepare('DELETE FROM password_resets WHERE expires_at < ?').bind(now).run();
      console.log(`[Cron] Expired reset tokens deleted: ${r.meta.changes}`);
    } catch (err) { console.error('[Cron] Reset token cleanup failed:', err.message); }

    // ── Clear expired email verification tokens ───────────────────────────────
    // Preserves the account row — users can request a fresh link at any time.
    try {
      const r = await env.DB.prepare(
        'UPDATE users SET email_verification_token = NULL, email_verification_expires = NULL ' +
        'WHERE email_verified = 0 AND email_verification_expires IS NOT NULL ' +
        'AND email_verification_expires < ?'
      ).bind(now).run();
      console.log(`[Cron] Expired verification tokens cleared: ${r.meta.changes}`);
    } catch (err) { console.error('[Cron] Verification token cleanup failed:', err.message); }

    // ── Delete stale sessions ────────────────────────────────────────────────
    try {
      const r = await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
      console.log(`[Cron] Stale sessions deleted: ${r.meta.changes}`);
    } catch (err) { console.error('[Cron] Session cleanup failed:', err.message); }

    // ── Prune old audit log records ──────────────────────────────────────────
    try {
      const cutoff = new Date(Date.now() - AUDIT_RETENTION_DAYS * 86400000).toISOString();
      const r = await env.DB.prepare('DELETE FROM audit_logs WHERE timestamp < ?').bind(cutoff).run();
      console.log(`[Cron] Audit records pruned (>${AUDIT_RETENTION_DAYS}d): ${r.meta.changes}`);
    } catch (err) { console.error('[Cron] Audit log cleanup failed:', err.message); }

    console.log('[Cron] Monthly maintenance complete');
  }
};

// ── EMAIL TEMPLATE BUILDERS ───────────────────────────────────────────────────
// Shared between /register (isResend=false) and /resend-verification (isResend=true).

function buildVerificationEmailHtml(verifyLink, isResend) {
  const bodyText   = isResend
    ? 'Here is your new verification link for Wissely. Click the button below to verify your email address and activate your account.'
    : 'Thanks for signing up for Wissely. Click the button below to verify your email address and activate your account.';
  const footerNote = isResend
    ? 'You received this email because a new verification link was requested for this account.'
    : 'You received this email because an account was created with this email address.';
  const ignoreNote = isResend
    ? 'If you did not request this, you can safely ignore this email.'
    : 'If you did not create a Wissely account, you can safely ignore this email.';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Verify your Wissely email</title>
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
                <tr><td style="height:3px;background:linear-gradient(90deg,#2d4a3e,#c9a84c,#2d4a3e);"></td></tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:40px 40px 36px;">
                    <p style="margin:0 0 18px;font-size:10px;font-family:'Courier New',monospace;letter-spacing:3px;text-transform:uppercase;color:#c9a84c;font-weight:600;">Email Verification</p>
                    <h1 style="margin:0 0 14px;font-family:Georgia,serif;font-size:32px;font-weight:600;color:#fefefc;letter-spacing:-1px;line-height:1.1;">
                      Verify your<br/><em style="font-style:italic;color:#e8c97a;">email address.</em>
                    </h1>
                    <p style="margin:0 0 32px;font-size:14px;color:rgba(255,255,255,0.6);line-height:1.85;">${bodyText}</p>
                    <table cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
                      <tr>
                        <td style="background-color:#c9a84c;border-radius:100px;">
                          <a href="${verifyLink}" style="display:inline-block;padding:14px 36px;font-size:14px;font-weight:600;color:#0c0c0a;text-decoration:none;font-family:'Segoe UI',Arial,sans-serif;letter-spacing:0.2px;">
                            Verify Email
                          </a>
                        </td>
                      </tr>
                    </table>
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
                      <tr>
                        <td style="background-color:rgba(45,74,62,0.25);border:1px solid rgba(45,74,62,0.45);border-left:3px solid #c9a84c;border-radius:10px;padding:14px 18px;">
                          <p style="margin:0;font-size:12px;color:rgba(255,255,255,0.6);line-height:1.6;font-family:'Courier New',monospace;">
                            <span style="color:#e8c97a;font-weight:600;">&#9679; EXPIRES IN 24 HOURS</span><br/>
                            ${ignoreNote}
                          </p>
                        </td>
                      </tr>
                    </table>
                    <p style="margin:0;font-size:12px;color:rgba(255,255,255,0.35);line-height:1.7;">
                      Button not working? Copy and paste this link:<br/>
                      <a href="${verifyLink}" style="color:#c9a84c;text-decoration:none;word-break:break-all;">${verifyLink}</a>
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
                      ${footerNote}
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
}

function buildPasswordResetEmailHtml(resetLink) {
  return `<!DOCTYPE html>
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
                <tr><td style="height:3px;background:linear-gradient(90deg,#2d4a3e,#c9a84c,#2d4a3e);"></td></tr>
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
                          <a href="${resetLink}" style="display:inline-block;padding:14px 36px;font-size:14px;font-weight:600;color:#0c0c0a;text-decoration:none;font-family:'Segoe UI',Arial,sans-serif;letter-spacing:0.2px;">
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
}

// ── SCHEMA MIGRATION REFERENCE ────────────────────────────────────────────────
// Apply to Cloudflare D1 before deploying this worker version.
//
// 1. sessions table — add csrf_token column if not present:
//    ALTER TABLE sessions ADD COLUMN csrf_token TEXT;
//
//    NOTE: sessions.id now stores a SHA-256 hex hash of the raw session token.
//    All existing sessions will be invalidated on deploy (users must log in again).
//    No schema change is required — the column type (TEXT) is unchanged.
//
// 2. Audit log table:
//    CREATE TABLE IF NOT EXISTS audit_logs (
//      id         TEXT PRIMARY KEY,
//      timestamp  TEXT NOT NULL,
//      user_id    TEXT,
//      ip         TEXT,
//      event_type TEXT NOT NULL,
//      result     TEXT NOT NULL,
//      metadata   TEXT
//    );
//
// 3. Indexes — apply all; IF NOT EXISTS makes them safe to re-run:
//    CREATE INDEX IF NOT EXISTS idx_users_email                ON users(email);
//    CREATE INDEX IF NOT EXISTS idx_sessions_user_id           ON sessions(user_id);
//    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at        ON sessions(expires_at);
//    CREATE INDEX IF NOT EXISTS idx_password_resets_user_id    ON password_resets(user_id);
//    CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at ON password_resets(expires_at);
//    CREATE INDEX IF NOT EXISTS idx_users_verification_token   ON users(email_verification_token);
//    CREATE INDEX IF NOT EXISTS idx_users_paddle_sub_id        ON users(paddle_subscription_id);
//    CREATE INDEX IF NOT EXISTS idx_users_paddle_cust_id       ON users(paddle_customer_id);
//    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp       ON audit_logs(timestamp);
//    CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id         ON audit_logs(user_id);
//    CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type      ON audit_logs(event_type);
//
// 4. Required Cloudflare environment variables / secrets for this version:
//    PADDLE_API_KEY              — Paddle API key (secret), used for both
//                                   transaction creation and customer lookups.
//    PADDLE_WEBHOOK_SECRET       — Paddle webhook signing secret (secret).
//    PADDLE_API_BASE              — optional, defaults to https://api.paddle.com
//                                   (override to https://sandbox-api.paddle.com
//                                   for sandbox testing).
//    PADDLE_CHECKOUT_SUCCESS_URL  — preferred return URL for hosted checkout;
//                                   should resolve to success.html on the
//                                   frontend. Falls back to
//                                   PADDLE_CHECKOUT_RETURN_URL if unset.
//    PADDLE_CHECKOUT_CANCEL_URL   — destination the frontend's success.html /
//                                   checkout.html should send the user to if
//                                   the hosted checkout indicates the payment
//                                   was not completed. Not sent to Paddle
//                                   directly (Paddle Billing v2 hosted
//                                   checkout supports a single return URL);
//                                   read by the frontend only.
//    PADDLE_BILLING_PORTAL_URL    — (optional) override the Paddle Customer
//                                   Portal base URL. Not required; the portal
//                                   URL is returned dynamically by the Paddle
//                                   API per-session via /billing-portal.
//    RATE_LIMIT_KV                — KV namespace binding for rate limiting,
//                                   login protection, CSRF/webhook monitoring,
//                                   and Paddle event idempotency.
//    DB                           — D1 database binding.
//    ANTHROPIC_API_KEY            — Anthropic API key (secret).
//    RESEND_API_KEY               — Resend API key (secret).
