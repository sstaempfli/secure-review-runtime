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
import { createServer } from 'node:http';

const PORT = Number(process.env.PORT ?? 3000);

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

  // CORS: reflect any origin + allow credentials (a textbook misconfiguration).
  if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Information disclosure
  res.setHeader('Server', 'demo-vulnerable/0.1.0 (Node ' + process.version + ')');

  // Cookie without HttpOnly / Secure / SameSite
  res.setHeader('Set-Cookie', 'session=demo-session-id; Path=/');

  if (url.pathname === '/.env') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('# fake env file (deliberately exposed for the demo)\nSECRET_KEY=demo-not-real\n');
    return;
  }

  // Reflected XSS — input is concatenated into HTML without escaping.
  const q = url.searchParams.get('q') ?? '';
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!DOCTYPE html><html><body>' +
      '<h1>vulnerable-target demo</h1>' +
      '<p>Search query: ' + q + '</p>' +
      '<form><input name="q" /><button>Search</button></form>' +
      '</body></html>',
  );
});

server.listen(PORT, () => {
  console.log(`vulnerable-target listening on http://localhost:${PORT}`);
});
