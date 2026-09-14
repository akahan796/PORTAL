// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — team (user) directory.
//
// GET  → the user list without password hashes (any logged-in user).
// POST → replace the user list (admins only). The client posts the full array;
//        this merges to preserve each user's password hash by id. New users
//        (ids not already present) default to the @dmin123 password.
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE, ensureUsers, findById, sha256, saveUsers, isAdmin, publicUser } from './_lib.js';

export const config = { runtime: 'edge' };
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default async function handler(request){
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);
  const users = await ensureUsers();
  const me = findById(users, sess.uid);
  if (!me) return json({ error: 'not_found' }, 404);

  if (request.method === 'GET') {
    return json({ configured: true, team: users.map(publicUser) }, 200);
  }

  if (request.method === 'POST') {
    if (!isAdmin(me.role)) return json({ error: 'forbidden', message: 'Only admins can manage the team.' }, 403);
    let posted = null;
    try { posted = (await request.json()).team; } catch (e) {}
    if (!Array.isArray(posted)) return json({ error: 'bad_request' }, 400);

    const byId = {}; users.forEach((u) => { byId[u.id] = u; });
    const def = await sha256(process.env.ACCESS_PASSWORD || '@dmin123');
    const merged = [];
    for (const u of posted) {
      const prev = byId[u.id];
      const { password, pwHash, ...rest } = u;            // never trust a client-supplied hash
      let hash = prev ? prev.pwHash : def;                 // new users → default @dmin123
      if (password) hash = await sha256(password);         // optional explicit set/reset
      merged.push({ ...rest, pwHash: hash });
    }
    await saveUsers(merged);
    return json({ configured: true, ok: true }, 200);
  }

  return json({ error: 'method_not_allowed' }, 405);
}
