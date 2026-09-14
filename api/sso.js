// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — Portal → project single sign-on hand-off.
//
// GET /api/sso?to=<esg|lcm|o365|lim>
//   Requires a valid portal session. Issues a short-lived, HMAC-signed token
//   (shared SSO_SECRET) and 302-redirects to the target project's /portal.html
//   with ?__sso=<token>. The project's middleware validates it and logs the
//   user in without a password prompt.
//
// Without SSO_SECRET configured, it simply redirects to the project (which will
// then show its own login) — so nothing breaks before the secret is set.
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE, ensureUsers, findById, isAdmin } from './_lib.js';

export const config = { runtime: 'edge' };

const TARGETS = {
  esg:  'https://esg-beige-one.vercel.app',
  lcm:  'https://lcm-onestreamux.vercel.app',
  o365: 'https://o365-zeta.vercel.app',
  lim:  'https://lim-smoky.vercel.app',
};
const LANDING = '/portal.html';

async function hmacHex(msg, secret){
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(request){
  const url = new URL(request.url);
  const to = String(url.searchParams.get('to') || '').toLowerCase();
  const base = TARGETS[to];
  if (!base) return new Response('Unknown target', { status: 404 });

  const redirect = (loc) => new Response(null, { status: 302, headers: { 'Location': loc, 'Cache-Control': 'no-store' } });

  // Must be a logged-in portal user.
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return redirect(new URL('/login.html', request.url).toString());

  const ssoSecret = process.env.SSO_SECRET;
  // Not configured yet → just send them to the project (it'll prompt normally).
  if (!ssoSecret) return redirect(base + LANDING);

  // Admins get editor rights on the project; everyone else is a viewer.
  let role = 'viewer';
  try {
    const users = await ensureUsers();
    const me = findById(users, sess.uid);
    if (me && isAdmin(me.role)) role = 'editor';
  } catch (e) { /* default viewer */ }

  const exp = String(Date.now() + 120000); // 2 minutes
  const sig = await hmacHex(exp + '.' + role, ssoSecret);
  const token = exp + '.' + role + '.' + sig;
  return redirect(base + LANDING + '?__sso=' + encodeURIComponent(token));
}
