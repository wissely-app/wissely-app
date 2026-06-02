// Wissely API Worker
// Deploy this on Cloudflare Workers
// Add ANTHROPIC_API_KEY as an environment variable in Cloudflare
// Ensure your D1 Database is bound to this worker as 'DB'

// Helper function to generate SHA-256 hash using Web Crypto API
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        }
      });
    }

    // Only allow POST requests for API endpoints
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { 
        status: 405,
        headers: { 'Access-Control-Allow-Origin': '*' }
      });
    }

    try {
      // =========================================================================
      // 1. POST /register
      // =========================================================================
      if (path === '/register') {
        const { email, password } = await request.json();

        if (!email || !password) {
          return new Response(JSON.stringify({ error: 'Email and password are required' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }

        // Check if the email already exists
        const existingUser = await env.DB.prepare(
          "SELECT email FROM users WHERE email = ?"
        ).bind(email).first();

        if (existingUser) {
          return new Response(JSON.stringify({
            error: "Email already registered"
          }), {
            status: 409,
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*"
            }
          });
        }

        // Generate custom values
        const id = crypto.randomUUID();
        const passwordHash = await sha256(password);
        const createdAt = new Date().toISOString();
        
        // Calculate trial end date (Current date + 14 days)
        const trialEndDate = new Date();
        trialEndDate.setDate(trialEndDate.getDate() + 14);
        const trialEnd = trialEndDate.toISOString();

        // Trial Defaults
        const plan = 'trial';
        const analysesLimit = 20;
        const analysesUsed = 0;

        try {
          // Explicit mapping matching your exact schema structure
          await env.DB.prepare(
            `INSERT INTO users (id, email, password_hash, plan, analyses_used, analyses_limit, trial_end, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(id, email, passwordHash, plan, analysesUsed, analysesLimit, trialEnd, createdAt)
          .run();

          return new Response(JSON.stringify({ success: true, message: 'User registered successfully' }), {
            status: 201,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });

        } catch (dbError) {
          return new Response(JSON.stringify({ error: 'User registration failed due to a database error.' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
      }

      // =========================================================================
      // 2. POST /login
      // =========================================================================
      if (path === '/login') {
        const { email, password } = await request.json();

        if (!email || !password) {
          return new Response(JSON.stringify({ error: 'Email and password are required' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }

        const passwordHash = await sha256(password);

        // Fetch targeted user metadata from D1 matching payload requirements
        const user = await env.DB.prepare(
          `SELECT id, email, plan, analyses_used, analyses_limit, trial_end 
           FROM users 
           WHERE email = ? AND password_hash = ?`
        )
        .bind(email, passwordHash)
        .first();

        if (!user) {
          return new Response(JSON.stringify({ error: 'Invalid email or password' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }

        return new Response(JSON.stringify({ success: true, user }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      // =========================================================================
      // 3. Claude API Functionality (Preserved Fallback/Default Route)
      // =========================================================================
      const body = await request.json();

      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 1000,
          messages: body.messages
        })
      });

      const data = await response.json();

      return new Response(JSON.stringify(data), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        }
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        }
      });
    }
  }
};
