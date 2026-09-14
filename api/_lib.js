// ─────────────────────────────────────────────────────────────────────────────
// Shared auth helpers for the portal's per-user login.
//
// Users live in KV under `portal_users` as { id, first, last, email, role,
// status, pwHash }. Sessions are stateless signed cookies:
//   value = "<uid>.<exp>.<hmac(uid.exp, SESSION_TOKEN)>"
// verified with HMAC-SHA256 keyed by the server-only SESSION_TOKEN secret.
// ─────────────────────────────────────────────────────────────────────────────

export const USERS_KEY = 'portal_users';
export const SESSION_COOKIE = 'portal_auth';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const enc = (s) => new TextEncoder().encode(String(s));
const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');

export async function sha256(s){ return hex(await crypto.subtle.digest('SHA-256', enc(s))); }

async function hmac(msg){
  const secret = process.env.SESSION_TOKEN || '';
  const key = await crypto.subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc(msg)));
}

export async function makeSession(uid){
  const payload = uid + '.' + (Date.now() + SESSION_TTL_MS);
  return payload + '.' + (await hmac(payload));
}
export async function verifySession(value){
  if (!value) return null;
  const i = value.lastIndexOf('.');
  if (i < 1) return null;
  const payload = value.slice(0, i), sig = value.slice(i + 1);
  if (sig !== (await hmac(payload))) return null;
  const j = payload.lastIndexOf('.');
  const uid = payload.slice(0, j), exp = Number(payload.slice(j + 1));
  if (!(exp > Date.now())) return null;
  return { uid, exp };
}

export function getCookie(req, name){
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : '';
}
export function sessionCookie(value){
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

function kvCreds(){
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '',
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '',
  };
}
export function kvConfigured(){ const { url, token } = kvCreds(); return !!(url && token); }
export async function kv(command){
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

export async function getUsers(){
  const r = await kv(['GET', USERS_KEY]);
  try { return r.ok && r.result ? JSON.parse(r.result) : []; } catch (e) { return []; }
}
export async function saveUsers(users){ return kv(['SET', USERS_KEY, JSON.stringify(users)]); }

// Seed the owner on first use so the workspace is never empty / never locked out.
export async function ensureUsers(){
  let users = await getUsers();
  if (!Array.isArray(users) || !users.length){
    users = [{
      id: 'u-alex', first: 'Alex', last: 'Kahan',
      email: 'alex.kahan@onestreamsoftware.com',
      role: 'Super Administrator', status: 'Active',
      pwHash: await sha256(process.env.ACCESS_PASSWORD || '@dmin123'),
    }];
    await saveUsers(users);
  }
  return users;
}

export function findByEmail(users, email){
  const e = String(email || '').trim().toLowerCase();
  return users.find((u) => String(u.email || '').trim().toLowerCase() === e) || null;
}
export function findById(users, id){ return users.find((u) => u.id === id) || null; }
export function isAdmin(role){ return role === 'Super Administrator' || role === 'UX Manager'; }
export function publicUser(u){ if (!u) return null; const { pwHash, ...rest } = u; return rest; }
