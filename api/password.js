// Vercel Edge Function — change the logged-in user's own password.
import { getCookie, verifySession, SESSION_COOKIE, ensureUsers, findById, sha256, saveUsers } from './_lib.js';

export const config = { runtime: 'edge' };
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default async function handler(request){
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);

  let body = {};
  try { body = await request.json(); } catch (e) {}
  const current = String(body.current || ''), next = String(body.next || '');
  if (next.length < 6) return json({ error: 'weak', message: 'New password must be at least 6 characters.' }, 400);

  const users = await ensureUsers();
  const me = findById(users, sess.uid);
  if (!me) return json({ error: 'not_found' }, 404);
  if ((await sha256(current)) !== me.pwHash) return json({ error: 'bad_current', message: 'Current password is incorrect.' }, 403);

  me.pwHash = await sha256(next);
  const res = await saveUsers(users);
  if (!res.ok) return json({ error: 'store_failed', message: 'Could not save the new password. Try again.' }, 500);
  return json({ ok: true }, 200);
}
