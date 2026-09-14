// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — validates the password on the SERVER.
//
// The active password is either a custom one the user set (stored as a SHA-256
// hash in KV under `portal_pw`, changeable via /api/password), or — until they
// set one — the ACCESS_PASSWORD environment variable. SESSION_TOKEN and
// ACCESS_PASSWORD are server-only env vars, never shipped to the browser.
//
// On a correct password it sets an HttpOnly, Secure session cookie and redirects
// to the portal; otherwise it bounces back to the login page with ?e=1.
// ─────────────────────────────────────────────────────────────────────────────

export const config = { runtime: 'edge' };

const COOKIE_NAME = 'portal_auth';           // must match middleware.js / logout.js
const REDIRECT_AFTER_LOGIN = '/portal.html'; // where a successful login lands
const PW_KEY = 'portal_pw';                  // KV key holding the SHA-256 of the custom password

function kvCreds(){
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '',
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '',
  };
}
async function kvGet(key){
  const { url, token } = kvCreds();
  if (!url || !token) return null;
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['GET', key]),
    });
    if (!r.ok) return null;
    const j = await r.json().catch(() => ({}));
    return j.result || null;
  } catch (e) { return null; }
}
async function sha256(s){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(request) {
  const origin = new URL(request.url).origin;
  if (request.method !== 'POST') {
    return Response.redirect(origin + '/login.html', 302);
  }

  let password = '';
  try {
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      password = (await request.json()).password || '';
    } else {
      const form = await request.formData();
      password = form.get('password') || '';
    }
  } catch (e) { /* ignore malformed body */ }

  const token = process.env.SESSION_TOKEN;
  const accessPw = process.env.ACCESS_PASSWORD;

  // A custom password (KV hash) takes precedence; otherwise the env password applies.
  const storedHash = await kvGet(PW_KEY);
  let valid;
  if (storedHash) {
    valid = (await sha256(password)) === storedHash;
  } else {
    valid = !!(accessPw && password === accessPw);
  }

  if (token && valid) {
    const headers = new Headers({ 'Location': origin + REDIRECT_AFTER_LOGIN, 'Cache-Control': 'no-store' });
    headers.append('Set-Cookie', `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`);
    return new Response(null, { status: 303, headers });
  }

  return new Response(null, {
    status: 303,
    headers: { 'Location': origin + '/login.html?e=1', 'Cache-Control': 'no-store' },
  });
}
