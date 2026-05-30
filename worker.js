export default {
  async fetch(r, env) {
    const h = {
      'Access-Control-Allow-Origin':'*',
      'Access-Control-Allow-Methods':'POST,OPTIONS',
      'Access-Control-Allow-Headers':'Content-Type'
    };
    if (r.method==='OPTIONS') return new Response(null,{headers:h});
    if (r.method!=='POST') return new Response('No',{status:405,headers:h});
    try {
      const b = await r.json();
      const res = await fetch('https://api.anthropic.com/v1/messages',{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'x-api-key':env.ANTHROPIC_API_KEY,
          'anthropic-version':'2023-06-01'
        },
        body:JSON.stringify({
          model:'claude-sonnet-4-20250514',
          max_tokens:1000,
          messages:b.messages
        })
      });
      const d = await res.json();
      return new Response(JSON.stringify(d),{headers:{...h,'Content-Type':'application/json'}});
    } catch(e) {
      return new Response(JSON.stringify({error:e.message}),{status:500,headers:{...h,'Content-Type':'application/json'}});
    }
  }
};
