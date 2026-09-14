// Vercel Edge Function — returns the currently logged-in user (no password hash).
import { getCookie, verifySession, SESSION_COOKIE, ensureUsers, findById, publicUser } from './_lib.js';

export const config = { runtime: 'edge' };
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default async function handler(request){
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);
  const users = await ensureUsers();
  const me = findById(users, sess.uid);
  if (!me) return json({ error: 'not_found' }, 404);
  return json({ user: publicUser(me) }, 200);
}
