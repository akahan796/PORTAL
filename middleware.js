// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Middleware — SERVER-SIDE access gate.
//
// Every request (except the login page, the auth API, and public assets) must
// carry a valid signed session cookie (issued by /api/login and verified with
// the SESSION_TOKEN secret). No valid session → redirect to /login.html.
// ─────────────────────────────────────────────────────────────────────────────

import { getCookie, verifySession, SESSION_COOKIE } from './api/_lib.js';

export const config = {
  matcher: ['/((?!api/|login\\.html|fonts/|brandmark\\.svg|logo\\.png|favicon\\.ico|robots\\.txt|assets/).*)'],
};

export default async function middleware(request){
  if (!process.env.SESSION_TOKEN) return; // not configured → stay open (no lock-out on first deploy)
  const sess = await verifySession(getCookie(request, SESSION_COOKIE));
  if (sess) return; // authenticated
  return Response.redirect(new URL('/login.html', request.url), 302);
}
