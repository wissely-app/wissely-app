export default {
  async fetch(r, env) {
    const h = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (r.method === 'OPTIONS') return new Response(null, {headers: h});
    if (r.method !== 'POST') return new Response('No', {status: 405, headers: h});

    try {
      const body = await r.json();

      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-6',
          max_tokens: 1000,
          messages: body.messages
        })
      });

      const text = await response.text();
      const status = response.status;

      // If not successful return the full error for debugging
      if (!response.ok) {
        return new Response(JSON.stringify({
          error: { message: 'API Error ' + status + ': ' + text }
        }), {
          headers: {...h, 'Content-Type': 'application/json'}
        });
      }

      return new Response(text, {
        headers: {...h, 'Content-Type': 'application/json'}
      });

    } catch(e) {
      return new Response(JSON.stringify({error: {message: 'Worker error: ' + e.message}}), {
        status: 500,
        headers: {...h, 'Content-Type': 'application/json'}
      });
    }
  }
};
