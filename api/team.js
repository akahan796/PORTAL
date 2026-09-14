// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — shared team-member store.
//
// GET  → returns the stored team array (any logged-in user).
// POST → replaces the stored team array with the posted one (any logged-in user).
//
// Storage is a Redis/KV store (Vercel KV or Upstash) reached over its REST API.
// Reads env: KV_REST_API_URL / KV_REST_API_TOKEN (or the UPSTASH_REDIS_REST_*
// equivalents). If the store isn't configured, GET reports { configured:false }
// and the browser falls back to localStorage, so the app still works.
//
// Access is gated by the same portal_auth session cookie as the rest of the app.
// ─────────────────────────────────────────────────────────────────────────────

export const config = { runtime: 'edge' };

const KEY = 'portal_team';

function cookie(req, name){
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : '';
}

function kvCreds(){
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '',
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '',
  };
}

async function kv(command){
  const { url, token } = kvCreds();
  if (!url || !token) return { configured: false };
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
  });
  if (!r.ok) return { configured: true, ok: false };
  const j = await r.json().catch(() => ({}));
  return { configured: true, ok: true, result: j.result };
}

const json = (body, status) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
});

export default async function handler(request){
  const authed = cookie(request, 'portal_auth') === process.env.SESSION_TOKEN && !!process.env.SESSION_TOKEN;
  if (!authed) return json({ error: 'unauthorized' }, 401);

  const { url, token } = kvCreds();
  const configured = !!(url && token);

  if (request.method === 'GET'){
    if (!configured) return json({ configured: false, team: null }, 200);
    const res = await kv(['GET', KEY]);
    let team = null;
    try { team = res.ok && res.result ? JSON.parse(res.result) : null; } catch (e) { team = null; }
    return json({ configured: true, team }, 200);
  }

  if (request.method === 'POST'){
    if (!configured) return json({ configured: false }, 200); // client keeps localStorage
    let team = null;
    try { team = (await request.json()).team; } catch (e) {}
    if (!Array.isArray(team)) return json({ error: 'bad_request' }, 400);
    await kv(['SET', KEY, JSON.stringify(team)]);
    return json({ configured: true, ok: true }, 200);
  }

  return json({ error: 'method_not_allowed' }, 405);
}
