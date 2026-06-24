/**
 * Wissely Core API Worker - Production Ready Delivery Module
 * Features: PBKDF2 Hashing, Secure HttpOnly Sessions, Subscription Limits,
 * CORS Verification, Hardened Security Response Headers, AI Report Validator
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

// Reusable system prompt injected into every AI request.
// Instructs the model to return structured JSON only — no prose, no markdown.
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

// Tool-specific prompt extensions. Each entry contains ONLY instructions unique
// to that tool. They are appended to AI_BASE_SYSTEM_PROMPT at request time via
// buildSystemPrompt() and must never duplicate global rules.
const AI_TOOL_PROMPTS = {
  "invoice-analyzer": `TOOL: Invoice Analyzer
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

  "expense-clarity": `TOOL: Expense Clarity
Your task is to analyze the provided expense data and identify patterns and savings.
Focus on:
- Categorizing every expense by type (travel, software, payroll, marketing, etc.)
- Identifying recurring vs one-time expenses
- Detecting unusually high spending in any category
- Calculating category totals and percentage of total spend
- Surfacing concrete savings opportunities
- Identifying trends across time periods if data allows
Populate the optional fields: expenseBreakdown, categoryTotals, insights, timeline.`,

  "finance-report": `TOOL: Finance Report
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

  "fraud-detection": `TOOL: Fraud Detection
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

  "cash-flow-forecast": `TOOL: Cash Flow Forecast
Your task is to project future cash flow based on the provided financial data.
Focus on:
- Projected income by period (weekly or monthly)
- Projected expenses by period
- Net cash flow per period
- Estimated cash runway (how many months of runway remain)
- Identification of upcoming cash shortages or pressure points
- Recommendations to extend runway or improve cash position
Populate the optional fields: cashFlow (array of period projections), timeline, warnings.`,

  "payment-request": `TOOL: Payment Request
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

// Returns the full system prompt for a given tool.
// Falls back to the base prompt if the tool is not registered.
function buildSystemPrompt(toolName) {
  const toolPrompt = AI_TOOL_PROMPTS[toolName];
  if (toolPrompt) {
    return AI_BASE_SYSTEM_PROMPT + '\n\n' + toolPrompt;
  }
  return AI_BASE_SYSTEM_PROMPT;
}

// Paddle price ID → internal plan mapping.
// Replace placeholder keys with your actual Paddle price IDs from the dashboard.
// analyses_limit is the monthly quota assigned when each plan activates.
const PADDLE_PRICE_PLANS = {
  'pri_REPLACE_starter_monthly':  { plan: 'starter',  analyses_limit: 50   },
  'pri_REPLACE_starter_yearly':   { plan: 'starter',  analyses_limit: 50   },
  'pri_REPLACE_pro_monthly':      { plan: 'pro',      analyses_limit: 200  },
  'pri_REPLACE_pro_yearly':       { plan: 'pro',      analyses_limit: 200  },
  'pri_REPLACE_business_monthly': { plan: 'business', analyses_limit: 1000 },
  'pri_REPLACE_business_yearly':  { plan: 'business', analyses_limit: 1000 },
};

// Fallback plan applied on cancellation, pause, or unrecognised price ID
const PLAN_FREE = { plan: 'free', analyses_limit: 5 };

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

// ── AI RESPONSE EXTRACTOR ────────────────────────────────────────────────────
// Accepts raw AI responses from any provider/format and returns a plain object.
// Never throws. Falls back to { rawText } if no JSON can be extracted.
function extractAIReport(rawResponse) {
  // Normalize to a string for uniform handling
  const raw = typeof rawResponse === 'string'
    ? rawResponse
    : JSON.stringify(rawResponse);

  // Helper: attempt JSON.parse, return null on failure
  function tryParse(str) {
    try { return JSON.parse(str); } catch { return null; }
  }

  // Helper: strip markdown code fences (```json ... ``` or ``` ... ```)
  function stripFences(str) {
    return str.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
  }

  // Format 1 — already a plain object (caller passed parsed JSON)
  if (typeof rawResponse === 'object' && rawResponse !== null && !Array.isArray(rawResponse)) {
    // Format 5 — Anthropic: { content: [{ text: "..." }] }
    if (Array.isArray(rawResponse.content)) {
      const textBlock = rawResponse.content.find(b => b && typeof b.text === 'string');
      if (textBlock) {
        const inner = tryParse(textBlock.text) ?? tryParse(stripFences(textBlock.text));
        if (inner) return inner;
        return { rawText: textBlock.text };
      }
    }
    // Format 6 — OpenAI: { choices: [{ message: { content: "..." } }] }
    if (Array.isArray(rawResponse.choices) && rawResponse.choices[0]?.message?.content) {
      const content = rawResponse.choices[0].message.content;
      const inner = tryParse(content) ?? tryParse(stripFences(content));
      if (inner) return inner;
      return { rawText: content };
    }
    // Already a plain report object — return as-is
    return rawResponse;
  }

  // Format 2 — raw JSON string
  const direct = tryParse(raw);
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) {
    // Re-run provider unwrapping on the parsed result
    return extractAIReport(direct);
  }

  // Format 3 / 4 — markdown fenced block (```json or ```)
  if (raw.includes('```')) {
    const stripped = stripFences(raw);
    const fromFence = tryParse(stripped);
    if (fromFence && typeof fromFence === 'object') return extractAIReport(fromFence);
  }

  // Format 7 — Cloudflare AI: { result: { response: "..." } } or { result: { ... } }
  const cf = tryParse(raw);
  if (cf?.result) {
    if (typeof cf.result === 'object') return extractAIReport(cf.result);
    if (typeof cf.result === 'string') {
      const inner = tryParse(cf.result) ?? tryParse(stripFences(cf.result));
      if (inner) return inner;
    }
  }

  // Format 8 — plain text / unrecognized: return as rawText, never throw
  return { rawText: raw };
}

// ── AI REPORT VALIDATOR ──────────────────────────────────────────────────────
// Guarantees every AI endpoint returns a valid, normalized Wissely Report object.
// Never throws. Missing fields are filled with safe defaults.
// Designed to be extended for future schema versions (v1.1, v2.0, etc.).
function validateAIReport(raw) {
  let report;

  // If raw is a string, attempt to parse it; on failure, start from scratch
  if (typeof raw === 'string') {
    try {
      report = JSON.parse(raw);
    } catch {
      report = {};
    }
  } else if (raw !== null && typeof raw === 'object') {
    report = raw;
  } else {
    report = {};
  }

  const VALID_STATUSES = new Set(['completed', 'warning', 'error']);

  return {
    // Preserve every extra field the AI returns (invoiceNumber, vendor, charts, etc.)
    // Required Wissely fields below override anything with the same key.
    ...report,

    schemaVersion:   typeof report.schemaVersion === 'string' && report.schemaVersion
                       ? report.schemaVersion
                       : '1.0',

    tool:            typeof report.tool === 'string' && report.tool
                       ? report.tool
                       : 'unknown',

    title:           typeof report.title === 'string' && report.title
                       ? report.title
                       : 'AI Report',

    status:          VALID_STATUSES.has(report.status)
                       ? report.status
                       : 'completed',

    generatedAt:     typeof report.generatedAt === 'string' && !isNaN(Date.parse(report.generatedAt))
                       ? report.generatedAt
                       : new Date().toISOString(),

    summary:         typeof report.summary === 'string' && report.summary
                       ? report.summary
                       : 'No summary available.',

    metrics:         Array.isArray(report.metrics)         ? report.metrics         : [],
    findings:        Array.isArray(report.findings)        ? report.findings        : [],
    risks:           Array.isArray(report.risks)           ? report.risks           : [],
    recommendations: Array.isArray(report.recommendations) ? report.recommendations : [],

    confidence:      (() => {
                       const c = Number(report.confidence);
                       if (!isFinite(c)) return 0;
                       return Math.min(100, Math.max(0, c));
                     })()
  };
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

// ── PADDLE WEBHOOK HELPERS ──────────────────────────────────────────────────
// Verify Paddle Billing v2 HMAC-SHA256 webhook signature.
// Header format: "ts=<unix_timestamp>;h1=<hex_signature>"
// Signed payload:  "<ts>:<rawBody>"
async function verifyPaddleSignature(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;

  const parts = {};
  for (const seg of signatureHeader.split(';')) {
    const eq = seg.indexOf('=');
    if (eq !== -1) parts[seg.slice(0, eq)] = seg.slice(eq + 1);
  }
  const { ts, h1 } = parts;
  if (!ts || !h1) return false;

  // Reject webhooks older than 5 minutes — prevents replay attacks
  const ageSeconds = Math.abs(Date.now() / 1000 - parseInt(ts, 10));
  if (ageSeconds > 300) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC', key, encoder.encode(`${ts}:${rawBody}`)
  );
  return safeCompare(bufToHex(signatureBuffer), h1);
}

// Resolve a Paddle subscription event into the appropriate DB update.
// Returns silently on unhandled event types — Paddle retries on 5xx only.
async function processPaddleEvent(eventType, data, env) {
  const subscriptionId = data?.id;
  const customerId     = data?.customer_id;
  const userId         = data?.custom_data?.user_id; // set at Paddle checkout time
  const status         = data?.status ?? 'unknown';
  const priceId        = data?.items?.[0]?.price?.id;
  const planConfig     = PADDLE_PRICE_PLANS[priceId]; // undefined = unrecognised price

  switch (eventType) {

    // ── New subscription or plan upgrade/downgrade ───────────────────────────
    case 'subscription.created':
    case 'subscription.updated': {
      const { plan, analyses_limit } = planConfig ?? PLAN_FREE;

      if (userId) {
        // Primary path: custom_data.user_id was injected at checkout
        await env.DB.prepare(
          "UPDATE users SET plan = ?, analyses_limit = ?, paddle_customer_id = ?, " +
          "paddle_subscription_id = ?, subscription_status = ? WHERE id = ?"
        ).bind(plan, analyses_limit, customerId, subscriptionId, status, userId).run();
      } else if (customerId) {
        // Fallback: match by paddle_customer_id stored from a prior event
        await env.DB.prepare(
          "UPDATE users SET plan = ?, analyses_limit = ?, paddle_subscription_id = ?, " +
          "subscription_status = ? WHERE paddle_customer_id = ?"
        ).bind(plan, analyses_limit, subscriptionId, status, customerId).run();
      } else {
        console.warn('[Paddle] subscription event received with no resolvable user — skipped');
      }
      break;
    }

    // ── Subscription canceled — revert to free tier ──────────────────────────
    case 'subscription.canceled': {
      await env.DB.prepare(
        "UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? " +
        "WHERE paddle_subscription_id = ?"
      ).bind(PLAN_FREE.plan, PLAN_FREE.analyses_limit, 'canceled', subscriptionId).run();
      break;
    }

    // ── Subscription paused (e.g. after grace period exhausted) ─────────────
    case 'subscription.paused': {
      await env.DB.prepare(
        "UPDATE users SET plan = ?, analyses_limit = ?, subscription_status = ? " +
        "WHERE paddle_subscription_id = ?"
      ).bind(PLAN_FREE.plan, PLAN_FREE.analyses_limit, 'paused', subscriptionId).run();
      break;
    }

    // ── Payment past due — flag without stripping access yet ─────────────────
    // Business decision: strip access only after subscription.paused/canceled.
    case 'subscription.past_due': {
      await env.DB.prepare(
        "UPDATE users SET subscription_status = ? WHERE paddle_subscription_id = ?"
      ).bind('past_due', subscriptionId).run();
      break;
    }

    default:
      console.log(`[Paddle] Unhandled event type ignored: ${eventType}`);
  }
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

      // ── HEALTH ──────────────────────────────────────────────────────────────
      if (path === '/health' && request.method === 'GET') {
        let dbStatus = 'ok';
        try {
          await env.DB.prepare("SELECT 1").first();
        } catch {
          dbStatus = 'error';
        }
        const healthy = dbStatus === 'ok';
        return createResponse(request, {
          status:    healthy ? 'ok' : 'degraded',
          version:   '1.0.0',
          timestamp: new Date().toISOString(),
          services:  { db: dbStatus }
        }, healthy ? 200 : 503);
      }

      // ── PADDLE WEBHOOK ───────────────────────────────────────────────────────
      if (path === '/webhook/paddle' && request.method === 'POST') {
        // Raw body must be read before any other parsing — required for HMAC verification
        const rawBody = await request.text();
        const signatureHeader = request.headers.get('Paddle-Signature');

        const isValid = await verifyPaddleSignature(
          env.PADDLE_WEBHOOK_SECRET, rawBody, signatureHeader
        );
        if (!isValid) {
          return createResponse(request, { error: 'Invalid webhook signature' }, 400);
        }

        let event;
        try {
          event = JSON.parse(rawBody);
        } catch {
          return createResponse(request, { error: 'Invalid JSON payload' }, 400);
        }

        const { event_type: eventType, data } = event;

        try {
          await processPaddleEvent(eventType, data, env);
        } catch (paddleErr) {
          // Log but always return 200 — prevents Paddle retrying our internal errors
          console.error('[Paddle] processPaddleEvent failed:', paddleErr.message);
        }

        return createResponse(request, { received: true }, 200);
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

        // Generate email verification token — same pattern as password reset
        const rawVerifyToken     = generateResetToken();
        const hashedVerifyToken  = await hashToken(rawVerifyToken);
        const verifyExpires      = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 h

        await env.DB.prepare(
          "INSERT INTO users (id, email, password_hash, password_salt, plan, analyses_used, analyses_limit, " +
          "trial_end, created_at, email_verified, email_verification_token, email_verification_expires) " +
          "VALUES (?, ?, ?, ?, 'trial', 0, 20, ?, ?, 0, ?, ?)"
        ).bind(id, email, hash, salt, trialEnd, new Date().toISOString(),
               hashedVerifyToken, verifyExpires).run();

        // Send verification email — non-fatal if Resend is temporarily unavailable
        try {
          const verifyLink = `https://app.wissely.com/verify-email.html?token=${rawVerifyToken}`;

          const verifyHtml = `<!DOCTYPE html>
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
                <tr>
                  <td style="height:3px;background:linear-gradient(90deg,#2d4a3e,#c9a84c,#2d4a3e);"></td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:40px 40px 36px;">
                    <p style="margin:0 0 18px;font-size:10px;font-family:'Courier New',monospace;letter-spacing:3px;text-transform:uppercase;color:#c9a84c;font-weight:600;">Email Verification</p>
                    <h1 style="margin:0 0 14px;font-family:Georgia,serif;font-size:32px;font-weight:600;color:#fefefc;letter-spacing:-1px;line-height:1.1;">
                      Verify your<br/><em style="font-style:italic;color:#e8c97a;">email address.</em>
                    </h1>
                    <p style="margin:0 0 32px;font-size:14px;color:rgba(255,255,255,0.6);line-height:1.85;">
                      Thanks for signing up for Wissely. Click the button below to verify your email address and activate your account.
                    </p>
                    <table cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
                      <tr>
                        <td style="background-color:#c9a84c;border-radius:100px;">
                          <a href="${verifyLink}"
                             style="display:inline-block;padding:14px 36px;font-size:14px;font-weight:600;color:#0c0c0a;text-decoration:none;font-family:'Segoe UI',Arial,sans-serif;letter-spacing:0.2px;">
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
                            If you did not create a Wissely account, you can safely ignore this email.
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
                      You received this email because an account was created with this email address.
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

          let verifyRes = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from: 'Wissely <noreply@wissely.com>',
              to: [email],
              subject: 'Verify your Wissely email address',
              html: verifyHtml,
              text: `Verify your Wissely email address: ${verifyLink}`
            })
          });
          if (!verifyRes.ok) {
            // Single retry on transient failure
            verifyRes = await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                from: 'Wissely <noreply@wissely.com>',
                to: [email],
                subject: 'Verify your Wissely email address',
                html: verifyHtml,
                text: `Verify your Wissely email address: ${verifyLink}`
              })
            });
            if (!verifyRes.ok) {
              const errText = await verifyRes.text();
              console.error(`[Register] Verification email failed after retry: ${verifyRes.status} - ${errText}`);
            }
          }
        } catch (emailErr) {
          console.error('[Register] Verification email exception:', emailErr);
        }

        return createResponse(request, {
          success: true,
          message: 'Account created. Please check your email to verify your account.',
          requiresVerification: true
        }, 201);
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
          "SELECT id, email, password_hash, password_salt, plan, analyses_used, analyses_limit, email_verified FROM users WHERE email = ?"
        ).bind(email).first();

        if (!user) return createResponse(request, { error: 'Invalid email or password' }, 401);

        const { hash } = await hashPassword(password, user.password_salt);

        // Constant-time comparison prevents timing attacks
        if (!safeCompare(hash, user.password_hash)) {
          return createResponse(request, { error: 'Invalid email or password' }, 401);
        }

        // Block login until email is verified
        if (!user.email_verified) {
          return createResponse(request, {
            error: 'Please verify your email address before logging in.',
            requiresVerification: true
          }, 403);
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

      // ── VERIFY EMAIL ────────────────────────────────────────────────────────
      if (path === '/verify-email' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'verify-email')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { token } = body;
        if (!token) return createResponse(request, { error: 'Verification token required' }, 400);
        if (token.length > MAX_TOKEN_LENGTH) return createResponse(request, { error: 'Invalid verification token' }, 400);

        const hashedToken = await hashToken(token);

        const targetUser = await env.DB.prepare(
          "SELECT id, email_verification_expires FROM users WHERE email_verification_token = ? AND email_verified = 0"
        ).bind(hashedToken).first();

        if (!targetUser) {
          return createResponse(request, { error: 'Invalid or already used verification link.' }, 400);
        }

        if (new Date().getTime() > new Date(targetUser.email_verification_expires).getTime()) {
          return createResponse(request, { error: 'Verification link has expired. Please request a new one.' }, 400);
        }

        await env.DB.prepare(
          "UPDATE users SET email_verified = 1, email_verification_token = NULL, email_verification_expires = NULL WHERE id = ?"
        ).bind(targetUser.id).run();

        return createResponse(request, {
          success: true,
          message: 'Email verified successfully. You can now log in.'
        }, 200);
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
            body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1000, system: buildSystemPrompt(body.tool || 'unknown'), messages: body.messages })
          });

          const rawPayload = await anthropicRes.text();

          if (anthropicRes.ok) {
            const updatedUser = await env.DB.prepare(
              "SELECT id, email, plan, analyses_used, analyses_limit, trial_end FROM users WHERE id = ?"
            ).bind(session.user_id).first();

            // Extract structured JSON from any provider format, then validate/normalize.
            // Neither call ever throws — malformed or partial AI output is always safe.
            const extractedReport = extractAIReport(rawPayload);
            const report = validateAIReport(extractedReport);

            return createResponse(request, {
              success: true,
              data: report,
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

      // ── RESEND VERIFICATION ─────────────────────────────────────────────────
      if (path === '/resend-verification' && request.method === 'POST') {
        if (await checkRateLimit(request, env, 'resend-verification')) {
          return createResponse(request, { error: 'Too many requests. Please try again later.' }, 429);
        }

        const { body, error: parseError } = await parseJsonBody(request);
        if (parseError) return createResponse(request, { error: parseError }, 400);

        const { email } = body;
        if (!email) return createResponse(request, { error: 'Email required' }, 400);

        // Standard enumeration-safe response — always returned regardless of outcome
        const standardResponse = createResponse(request, {
          success: true,
          message: 'If the account exists and is not yet verified, a new verification email has been sent.'
        }, 200);

        // Input length guard — bail early but return standard response
        if (email.length > MAX_EMAIL_LENGTH) return standardResponse;

        const user = await env.DB.prepare(
          "SELECT id, email_verified FROM users WHERE email = ?"
        ).bind(email).first();

        // Only act if the user exists and is unverified — never reveal which case applies
        if (user && !user.email_verified) {
          const rawVerifyToken    = generateResetToken();
          const hashedVerifyToken = await hashToken(rawVerifyToken);
          const verifyExpires     = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

          await env.DB.prepare(
            "UPDATE users SET email_verification_token = ?, email_verification_expires = ? WHERE id = ?"
          ).bind(hashedVerifyToken, verifyExpires, user.id).run();

          try {
            const verifyLink = `https://app.wissely.com/verify-email.html?token=${rawVerifyToken}`;

            const verifyHtml = `<!DOCTYPE html>
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
                <tr>
                  <td style="height:3px;background:linear-gradient(90deg,#2d4a3e,#c9a84c,#2d4a3e);"></td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:40px 40px 36px;">
                    <p style="margin:0 0 18px;font-size:10px;font-family:'Courier New',monospace;letter-spacing:3px;text-transform:uppercase;color:#c9a84c;font-weight:600;">Email Verification</p>
                    <h1 style="margin:0 0 14px;font-family:Georgia,serif;font-size:32px;font-weight:600;color:#fefefc;letter-spacing:-1px;line-height:1.1;">
                      Verify your<br/><em style="font-style:italic;color:#e8c97a;">email address.</em>
                    </h1>
                    <p style="margin:0 0 32px;font-size:14px;color:rgba(255,255,255,0.6);line-height:1.85;">
                      Here is your new verification link for Wissely. Click the button below to verify your email address and activate your account.
                    </p>
                    <table cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
                      <tr>
                        <td style="background-color:#c9a84c;border-radius:100px;">
                          <a href="${verifyLink}"
                             style="display:inline-block;padding:14px 36px;font-size:14px;font-weight:600;color:#0c0c0a;text-decoration:none;font-family:'Segoe UI',Arial,sans-serif;letter-spacing:0.2px;">
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
                            If you did not request this, you can safely ignore this email.
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
                      You received this email because a new verification link was requested for this account.
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

            let resendRes = await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                from: 'Wissely <noreply@wissely.com>',
                to: [email],
                subject: 'Verify your Wissely email address',
                html: verifyHtml,
                text: `Verify your Wissely email address: ${verifyLink}`
              })
            });
            if (!resendRes.ok) {
              resendRes = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  from: 'Wissely <noreply@wissely.com>',
                  to: [email],
                  subject: 'Verify your Wissely email address',
                  html: verifyHtml,
                  text: `Verify your Wissely email address: ${verifyLink}`
                })
              });
              if (!resendRes.ok) {
                const errText = await resendRes.text();
                console.error(`[ResendVerification] Email failed after retry: ${resendRes.status} - ${errText}`);
              }
            }
          } catch (emailErr) {
            console.error('[ResendVerification] Email exception:', emailErr);
          }
        }

        return standardResponse;
      }

      return createResponse(request, { error: 'Not found' }, 404);
    } catch (globalError) {
      console.error('[Worker] Unhandled exception:', globalError.message);
      return createResponse(request, { error: 'An unexpected error occurred' }, 500);
    }
  },

  // ── CRON: Monthly usage reset ────────────────────────────────────────────
  // Triggered by wrangler.toml cron schedule: "0 0 1 * *" (00:00 UTC, 1st of month)
  // The UTC date check inside is a safety net against misconfigured schedules.
  async scheduled(event, env, ctx) {
    const today = new Date();
    if (today.getUTCDate() !== 1) {
      console.log('[Cron] Monthly reset skipped — not the 1st of the month (UTC)');
      return;
    }
    try {
      const result = await env.DB.prepare(
        "UPDATE users SET analyses_used = 0"
      ).run();
      console.log(`[Cron] Monthly usage reset complete — ${result.meta.changes} user(s) reset`);
    } catch (err) {
      console.error('[Cron] Monthly usage reset failed:', err.message);
    }
  }
};
