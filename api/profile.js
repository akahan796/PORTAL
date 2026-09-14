// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — update the logged-in user's OWN profile.
// POST { first?, last?, email?, avatar? }
//   avatar: a small "data:image/..." data URL, "" / null to remove.
// Returns { ok:true, user } (without password hash).
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE, ensureUsers, findById, saveUsers, publicUser } from './_lib.js';

export const config = { runtime: 'edge' };
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export default async function handler(request){
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);

  let body = {};
  try { body = await request.json(); } catch (e) {}

  const users = await ensureUsers();
  const me = findById(users, sess.uid);
  if (!me) return json({ error: 'not_found' }, 404);

  if (typeof body.first === 'string') {
    const f = body.first.trim();
    if (!f) return json({ error: 'bad_request', message: 'First name is required.' }, 400);
    me.first = f.slice(0, 60);
  }
  if (typeof body.last === 'string') me.last = body.last.trim().slice(0, 60);

  if (typeof body.email === 'string') {
    const e = body.email.trim().toLowerCase();
    if (e) {
      if (!EMAIL_RE.test(e)) return json({ error: 'bad_email', message: 'Enter a valid email address.' }, 400);
      const clash = users.some((u) => u.id !== me.id && String(u.email || '').toLowerCase() === e);
      if (clash) return json({ error: 'email_taken', message: 'Another member already uses that email.' }, 409);
    }
    me.email = e;
  }

  if ('avatar' in body) {
    if (body.avatar === null || body.avatar === '') {
      delete me.avatar;
    } else if (typeof body.avatar === 'string' && body.avatar.indexOf('data:image/') === 0) {
      if (body.avatar.length > 400000) return json({ error: 'too_large', message: 'That image is too large — try a smaller photo.' }, 400);
      me.avatar = body.avatar;
    } else {
      return json({ error: 'bad_avatar', message: 'Unsupported image.' }, 400);
    }
  }

  const res = await saveUsers(users);
  if (!res.ok) return json({ error: 'store_failed', message: 'Could not save your changes. Try again.' }, 500);
  return json({ ok: true, user: publicUser(me) }, 200);
}
