// ─────────────────────────────────────────────────────────────────────────────
// Vercel Edge Function — signs the user out on the SERVER.
//
// The session cookie is HttpOnly (not reachable from browser JavaScript), so
// clearing it must happen here: we overwrite it with an expired cookie
// (Max-Age=0) and redirect to the login page.
// ─────────────────────────────────────────────────────────────────────────────

export const config = { runtime: 'edge' };

const COOKIE_NAME = 'portal_auth'; // must match middleware.js / login.js

export default function handler(request) {
  const origin = new URL(request.url).origin;
  const headers = new Headers({ 'Location': origin + '/login.html', 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  return new Response(null, { status: 303, headers });
}
