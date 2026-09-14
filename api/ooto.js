// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — OOTO coverage board store (portal_ooto in KV).
//
// Access rules (enforced here, not just in the UI):
//   • Owner  (OWNER_EMAIL, default akahan@onestreamsoftware.com) — full edit.
//   • Designer (a login that maps to a Jason/Lele tab) — may only change the
//     `dnotes` on their OWN existing projects. All other posted fields, other
//     designers, project add/remove, and the Information block are ignored.
//   • Anyone else — read-only (403 on write).
//
// Data shape: { info:{start,end,notes}, designers:[ { key, name, projects:[
//   { id, title, url, notes, contacts, dnotes } ] } ] }.
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE, kv, ensureUsers, findById } from './_lib.js';

export const config = { runtime: 'edge' };
const KEY = 'portal_ooto';
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

const OWNER_EMAIL = (process.env.OWNER_EMAIL || 'akahan@onestreamsoftware.com').toLowerCase();
const DESIGNERS = [
  { key: 'jason', name: 'Jason', emails: ['jkrause@onestreamsoftware.com'] },
  { key: 'lele',  name: 'Lele',  emails: ['lnelson@onestreamsoftware.com'] },
];
// Map a user to a designer tab by their login email, falling back to first name.
function designerKeyFor(me){
  if (!me) return null;
  const email = String(me.email || '').toLowerCase();
  const first = String(me.first || '').toLowerCase();
  for (const d of DESIGNERS){
    if (d.emails.some((e) => e.toLowerCase() === email)) return d.key;
    if (first && first === d.name.toLowerCase()) return d.key;
  }
  return null;
}

async function readData(){
  const r = await kv(['GET', KEY]);
  try { return r.ok && r.result ? JSON.parse(r.result) : null; } catch (e) { return null; }
}

export default async function handler(request){
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);

  const users = await ensureUsers();
  const me = findById(users, sess.uid);
  if (!me) return json({ error: 'not_found' }, 404);
  const email = String(me.email || '').toLowerCase();
  const isOwner = email === OWNER_EMAIL;
  const dkey = designerKeyFor(me);

  if (request.method === 'GET'){
    const data = await readData();
    return json({ configured: true, data, perms: { owner: isOwner, designerKey: dkey } }, 200);
  }

  if (request.method === 'POST'){
    let posted = null;
    try { posted = (await request.json()).data; } catch (e) {}
    if (!posted || typeof posted !== 'object') return json({ error: 'bad_request' }, 400);

    // Owner: full replace.
    if (isOwner){
      await kv(['SET', KEY, JSON.stringify(posted)]);
      return json({ ok: true }, 200);
    }

    // Designer: merge only their own projects' dnotes onto the stored data.
    if (dkey){
      const stored = (await readData()) || { info: { start: '', end: '', notes: '' }, designers: [] };
      if (!Array.isArray(stored.designers)) stored.designers = [];
      const mySection = stored.designers.find((d) => d.key === dkey);
      if (mySection && Array.isArray(mySection.projects)){
        const postedSection = Array.isArray(posted.designers) ? posted.designers.find((d) => d.key === dkey) : null;
        const byId = {};
        if (postedSection && Array.isArray(postedSection.projects)) postedSection.projects.forEach((p) => { if (p && p.id) byId[p.id] = p; });
        mySection.projects.forEach((p) => {
          const q = byId[p.id];
          if (q && typeof q.dnotes === 'string') p.dnotes = q.dnotes.slice(0, 5000);
        });
      }
      await kv(['SET', KEY, JSON.stringify(stored)]);
      return json({ ok: true, limited: true }, 200);
    }

    return json({ error: 'forbidden', message: 'You can view this board but not edit it.' }, 403);
  }

  return json({ error: 'method_not_allowed' }, 405);
}
