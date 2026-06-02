/**
 * Wissely Core API Worker - Production Ready Delivery Module
 * Features: PBKDF2 Hashing, Secure HttpOnly Sessions, Subscription Limits & CORS Verification
 */

// Explicit allowed origin whitelist for secure CORS isolation
const ALLOWED_ORIGINS = [
  'https://wissely.com',
  'https://www.wissely.com',
  'https://app.wissely.com',
  'https://wissely-worker.thilinarashmika0727.workers.dev'
];

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

function createResponse(request, data, status = 200, headers = {}) {
  const origin = getAllowedOrigin(request);
  const corsHeaders = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers': 'Set-Cookie'
  };
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, ...headers } });
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
  async fetch(request, env) {
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
        }
      });
    }

    try {
      // Aggressive database housekeeping for expired sessions
      if (Math.random() < 0.05) {
        const nowIso = new Date().toISOString();
        await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(nowIso).run();
      }

      if (path === '/register' && request.method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return createResponse(request, { error: 'Email and password required' }, 400);

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

      if (path === '/login' && request.method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return createResponse(request, { error: 'Fields required' }, 400);

        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (!user) return createResponse(request, { error: 'Invalid email or password' }, 401);

        const { hash } = await hashPassword(password, user.password_salt);
        if (hash !== user.password_hash) return createResponse(request, { error: 'Invalid email or password' }, 401);

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

      if (path === '/me' && request.method === 'GET') {
        const session = await authenticateSession(request, env);
        if (!session) return createResponse(request, { error: 'Unauthenticated' }, 401);
        if (session.isExpiredTrial) return createResponse(request, { error: 'Trial expired', user: session }, 403);

        return createResponse(request, {
          authenticated: true,
          user: { id: session.user_id, email: session.email, plan: session.plan, analyses_used: session.analyses_used, analyses_limit: session.analyses_limit }
        });
      }

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

      if (path === '/analyze' && request.method === 'POST') {
        const session = await authenticateSession(request, env);
        if (!session) return createResponse(request, { error: 'Unauthorized session window' }, 401);
        if (session.isExpiredTrial) return createResponse(request, { error: 'Usage suspended: Trial expired' }, 403);

        const allocation = await env.DB.prepare(
          "UPDATE users SET analyses_used = analyses_used + 1 WHERE id = ? AND analyses_used < analyses_limit"
        ).bind(session.user_id).run();

        if (allocation.meta.changes === 0) {
          return createResponse(request, { error: 'Usage limit reached for this month' }, 403);
        }

        const body = await request.json();
        if (!body.messages) {
          await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
          return createResponse(request, { error: 'Missing chat trace history' }, 400);
        }

        try {
          console.log("[Analyze] Initializing Anthropic system outbound dispatch.");
          console.log(`[Analyze] Integration Check -> ANTHROPIC_API_KEY Present: ${!!env.ANTHROPIC_API_KEY}`);

          const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': env.ANTHROPIC_API_KEY,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, messages: body.messages })
          });

          console.log(`[Analyze] Anthropic execution cycle complete. HTTP Status: ${anthropicRes.status}`);
          
          // Clone response stream to inspect payload without disturbing original pipeline execution
          const loggedRes = anthropicRes.clone();
          const rawPayload = await loggedRes.text();
          console.log("[Analyze] Raw Upstream Body String payload output:", rawPayload);

          let data;
          try {
            data = JSON.parse(rawPayload);
          } catch(e) {
            data = { rawTextFallback: rawPayload };
          }

          if (anthropicRes.ok) {
            return createResponse(request, { success: true, data });
          } else {
            await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
            
            // Forward actual error telemetry back to client interface
            const outErrorMsg = (data && data.error && data.error.message) 
              || `Upstream system dropped connection with code: ${anthropicRes.status}`;
              
            return createResponse(request, { 
              error: outErrorMsg, 
              upstream: data 
            }, 502);
          }
        } catch (apiError) {
          console.error("[Analyze] Critical runtime exception during request dispatch:", apiError);
          await env.DB.prepare("UPDATE users SET analyses_used = analyses_used - 1 WHERE id = ?").bind(session.user_id).run();
          throw apiError;
        }
      }

      return createResponse(request, { error: 'Endpoint or Method not matched' }, 404);
    } catch (globalError) {
      return createResponse(request, { error: globalError.message }, 500);
    }
  }
};
