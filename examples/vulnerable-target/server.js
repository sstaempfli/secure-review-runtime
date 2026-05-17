#!/usr/bin/env node
// DELIBERATELY VULNERABLE — for demonstrating secure-review-runtime probes.
// DO NOT deploy. Run locally and point `attack` at http://localhost:3000.
//
// Vulnerabilities baked in (so the scanner has something to find):
//   - Reflected XSS via the `q` query parameter (output is not escaped).
//   - No Content-Security-Policy header.
//   - No X-Frame-Options / no clickjacking protection.
//   - No Strict-Transport-Security (HSTS).
//   - No X-Content-Type-Options.
//   - Sets a cookie WITHOUT HttpOnly, Secure, or SameSite attributes.
//   - CORS reflects the Origin header verbatim with credentials → trust-everyone.
//   - Exposes a fake /.env path (sensitive-paths probe).
//   - Server header advertises a version (information disclosure).
//
// Plus a JS-rendered + login-gated section that ONLY the Playwright
// crawler (`attack-ai --playwright`) can reach — see the routes below
// and "Why --playwright" in this folder's README:
//   - GET /app           : empty SPA shell; links/form + an XHR to
//                           /api/nav are created at runtime by JS, so
//                           they are invisible in the raw HTML a curl /
//                           fetch crawler sees.
//   - GET /api/nav        : JSON the shell fetches at runtime (an API
//                           endpoint only a real browser discovers).
//   - GET /dashboard      : 302 → /login unless `session=` cookie set;
//                           with it, exposes an /admin/export link
//                           (authenticated-crawl + IDOR-ish surface).
import { createServer } from 'node:http';

const PORT = Number(process.env.PORT ?? 3000);

// Empty shell: NO href/form literals in the served markup. The browser
// builds the DOM (and fires the /api/nav XHR) only after executing this
// script — which a fetch/curl crawler never does.
const SPA_SHELL = `<!DOCTYPE html><html><head><title>spa-demo</title></head>
<body><div id="root"></div>
<script type="module">
  const root = document.getElementById('root');
  const res = await fetch('/api/nav?role=guest').then(r => r.json()).catch(() => ({ items: [] }));
  for (const item of res.items) {
    const a = document.createElement('a');
    a.href = item.url;
    a.textContent = item.label;
    root.appendChild(a);
  }
  const f = document.createElement('form');
  f.action = '/search';
  f.method = 'GET';
  const i = document.createElement('input');
  i.name = 'q';
  f.appendChild(i);
  root.appendChild(f);
</script></body></html>`;

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  const cookie = req.headers.cookie ?? '';

  // CORS: reflect any origin + allow credentials (a textbook misconfiguration).
  if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Information disclosure
  res.setHeader('Server', 'demo-vulnerable/0.1.0 (Node ' + process.version + ')');

  // Weak cookie (no HttpOnly / Secure / SameSite) — set ONLY on the
  // landing path `/` (what `attack` mode probes for the cookie finding).
  // Setting it on any page the authenticated crawl traverses would
  // overwrite the injected real session cookie mid-crawl and the
  // Playwright demo would never reach /dashboard.
  const setWeakCookie = () =>
    res.setHeader('Set-Cookie', 'session=demo-session-id; Path=/');

  if (url.pathname === '/.env') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('# fake env file (deliberately exposed for the demo)\nSECRET_KEY=demo-not-real\n');
    return;
  }

  // JS-rendered single-page app shell (the curl/fetch crawler sees an
  // empty <div id="root"> and nothing else).
  if (url.pathname === '/app') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(SPA_SHELL);
    return;
  }

  // Runtime API the shell calls via fetch() — only discoverable by a
  // crawler that actually executes the page.
  if (url.pathname === '/api/nav') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        items: [
          { label: 'Profile', url: '/profile' },
          { label: 'Dashboard', url: '/dashboard' },
        ],
      }),
    );
    return;
  }

  if (url.pathname === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!DOCTYPE html><html><body><h1>Login required</h1></body></html>');
    return;
  }

  // Login-gated: a fetch/curl crawler (no session cookie) is bounced to
  // /login. The Playwright crawler, given cookies from
  // --browser-login-script, gets the real page and discovers the
  // privileged /admin/export endpoint behind it.
  if (url.pathname === '/dashboard') {
    if (!/(^|;\s*)session=/.test(cookie) || cookie.includes('session=demo-session-id')) {
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      '<!DOCTYPE html><html><body><h1>Secret dashboard</h1>' +
        '<p>Logged-in-only content.</p>' +
        '<a id="export" href="/admin/export?account=1001">Export account data</a>' +
        '</body></html>',
    );
    return;
  }

  if (url.pathname === '/admin/export') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ account: url.searchParams.get('account'), pii: 'demo-not-real' }));
    return;
  }

  // Reflected XSS — input is concatenated into HTML without escaping.
  // The weak cookie is set only for the landing path `/` (see above);
  // other catch-all paths like /profile must not clobber a real session.
  const q = url.searchParams.get('q') ?? '';
  if (url.pathname === '/') setWeakCookie();
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!DOCTYPE html><html><body>' +
      '<h1>vulnerable-target demo</h1>' +
      '<p>Search query: ' + q + '</p>' +
      '<form><input name="q" /><button>Search</button></form>' +
      '<p><a href="/app">Single-page-app section</a></p>' +
      '</body></html>',
  );
});

server.listen(PORT, () => {
  console.log(`vulnerable-target listening on http://localhost:${PORT}`);
});
