// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — OOTO coverage board store (portal_ooto in KV).
//
// GET  → the coverage data (any logged-in user).
// POST → replaces it (any logged-in user — the covering designers edit their
//        own notes here). Structure: { designers: [ { key, name, projects:[
//        { id, title, notes, contacts, dnotes } ] } ] }.
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE, kv } from './_lib.js';

export const config = { runtime: 'edge' };
const KEY = 'portal_ooto';
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default async function handler(request){
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);

  if (request.method === 'GET'){
    const r = await kv(['GET', KEY]);
    let data = null;
    try { data = r.ok && r.result ? JSON.parse(r.result) : null; } catch (e) { data = null; }
    return json({ configured: true, data }, 200);
  }

  if (request.method === 'POST'){
    let data = null;
    try { data = (await request.json()).data; } catch (e) {}
    if (!data || typeof data !== 'object') return json({ error: 'bad_request' }, 400);
    await kv(['SET', KEY, JSON.stringify(data)]);
    return json({ ok: true }, 200);
  }

  return json({ error: 'method_not_allowed' }, 405);
}
