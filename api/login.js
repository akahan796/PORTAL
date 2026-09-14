// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — per-user login.
//
// POST { email, password }:
//   • With an email → looks the user up in KV and checks their password.
//   • Without an email → admin recovery: the password is checked against the
//     owner's password or the ACCESS_PASSWORD env var (@dmin123), logging in as
//     the owner. This is a break-glass so the workspace can't be locked out.
// On success, issues a signed session cookie and redirects to the portal.
// ─────────────────────────────────────────────────────────────────────────────

import { ensureUsers, findByEmail, sha256, makeSession, sessionCookie } from './_lib.js';

export const config = { runtime: 'edge' };

function bounce(origin){
  return new Response(null, { status: 303, headers: { 'Location': origin + '/login.html?e=1', 'Cache-Control': 'no-store' } });
}

export default async function handler(request){
  const origin = new URL(request.url).origin;
  if (request.method !== 'POST') return Response.redirect(origin + '/login.html', 302);
  if (!process.env.SESSION_TOKEN) return bounce(origin);

  let email = '', password = '';
  try {
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('application/json')) { const b = await request.json(); email = b.email || ''; password = b.password || ''; }
    else { const f = await request.formData(); email = f.get('email') || ''; password = f.get('password') || ''; }
  } catch (e) {}

  const users = await ensureUsers();
  const pwHash = await sha256(password);
  let uid = null;

  const em = String(email).trim();
  if (em) {
    const u = findByEmail(users, em);
    if (u && u.pwHash && pwHash === u.pwHash) uid = u.id;
  } else {
    // Admin recovery — password only, logs in as the owner.
    const owner = users.find((u) => u.role === 'Super Administrator') || users[0];
    const envPw = process.env.ACCESS_PASSWORD || '';
    if (owner && ((envPw && password === envPw) || (owner.pwHash && pwHash === owner.pwHash))) uid = owner.id;
  }

  if (uid) {
    const headers = new Headers({ 'Location': origin + '/portal.html', 'Cache-Control': 'no-store' });
    headers.append('Set-Cookie', sessionCookie(await makeSession(uid)));
    return new Response(null, { status: 303, headers });
  }
  return bounce(origin);
}
