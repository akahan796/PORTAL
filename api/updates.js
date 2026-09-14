// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — live "last updated" dates for the solution tiles.
//
// GET /api/updates?repos=ESG,LCM,O365,LIM,ODS
//   → { configured:true, dates:{ ESG:'2026-09-10', ... } }
//     using each repo's GitHub `pushed_at` (the latest push to that repo).
//
// Requires a read-only token in Vercel env: GITHUB_TOKEN (a classic/fine-grained
// PAT with repo:read). Owner defaults to GITHUB_OWNER || 'akahan796'.
// Without a token it returns { configured:false } and the client keeps the
// dates baked into the tiles — so the portal never breaks if it's absent.
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE } from './_lib.js';

export const config = { runtime: 'edge' };
const json = (b, s) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default async function handler(request){
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (!sess) return json({ error: 'unauthorized' }, 401);

  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) return json({ configured: false }, 200);

  const owner = process.env.GITHUB_OWNER || 'akahan796';
  const url = new URL(request.url);
  const repos = (url.searchParams.get('repos') || '')
    .split(',').map((s) => s.trim()).filter(Boolean).slice(0, 20);

  const dates = {};
  await Promise.all(repos.map(async (name) => {
    try {
      const r = await fetch(`https://api.github.com/repos/${owner}/${encodeURIComponent(name)}`, {
        headers: { Authorization: `token ${token}`, 'User-Agent': 'onestream-ux-portal', Accept: 'application/vnd.github+json' },
      });
      if (!r.ok) return;
      const d = await r.json();
      if (d && d.pushed_at) dates[name] = String(d.pushed_at).slice(0, 10);
    } catch (e) { /* leave this repo on its static date */ }
  }));

  return json({ configured: true, dates }, 200);
}
