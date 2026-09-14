// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — change the portal access password.
//
// POST { current, next } from a logged-in session:
//  • verifies `current` against the active password (KV hash if set, else the
//    ACCESS_PASSWORD env var),
//  • stores SHA-256(next) in KV under `portal_pw`.
// After this, /api/login validates against the new hash; the env password no
// longer works. Requires a KV store (Upstash Redis) to be configured.
// ─────────────────────────────────────────────────────────────────────────────

export const config = { runtime: 'edge' };

const PW_KEY = 'portal_pw';

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
async function sha256(s){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
const json = (body, status) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
});

export default async function handler(request){
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

  const authed = cookie(request, 'portal_auth') === process.env.SESSION_TOKEN && !!process.env.SESSION_TOKEN;
  if (!authed) return json({ error: 'unauthorized' }, 401);

  const { url, token } = kvCreds();
  if (!(url && token)) return json({ error: 'no_store', message: 'Password storage is not configured.' }, 501);

  let body = {};
  try { body = await request.json(); } catch (e) {}
  const current = String(body.current || '');
  const next = String(body.next || '');

  if (next.length < 6) return json({ error: 'weak', message: 'New password must be at least 6 characters.' }, 400);

  // Verify the current password against the active one (KV hash, else env).
  const stored = await kv(['GET', PW_KEY]);
  const storedHash = stored.ok && stored.result ? stored.result : null;
  let currentOk;
  if (storedHash) currentOk = (await sha256(current)) === storedHash;
  else currentOk = !!(process.env.ACCESS_PASSWORD && current === process.env.ACCESS_PASSWORD);
  if (!currentOk) return json({ error: 'bad_current', message: 'Current password is incorrect.' }, 403);

  const res = await kv(['SET', PW_KEY, await sha256(next)]);
  if (!res.ok) return json({ error: 'store_failed', message: 'Could not save the new password. Try again.' }, 500);

  return json({ ok: true }, 200);
}
