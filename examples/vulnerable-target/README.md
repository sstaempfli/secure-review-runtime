# vulnerable-target — quickstart demo

A 50-line, zero-dependency HTTP server with deliberate security flaws so
you can see what `secure-review-runtime attack` reports against a real
target without hosting one.

> [!warning]
> **Do not deploy this server.** It is intentionally insecure. Run it
> locally only and stop it when you're done with the demo.

## Vulnerabilities baked in

- Reflected XSS via the `q` query parameter
- Missing Content-Security-Policy
- Missing X-Frame-Options
- Missing Strict-Transport-Security (HSTS)
- Missing X-Content-Type-Options
- Cookie set without `HttpOnly` / `Secure` / `SameSite`
- CORS reflects any Origin with credentials enabled
- Sensitive path exposed at `/.env`
- Information disclosure via `Server:` header

## Run it

```sh
node server.js
# vulnerable-target listening on http://localhost:3000
```

In a second terminal, from the package root:

```sh
npx secure-review-runtime attack . --target-url http://localhost:3000
```

Expected: a Markdown report under `./reports/` with findings for the
header gaps, sensitive path, and cookie attributes (the AI-planned
`attack-ai` mode adds reflected XSS detection on top, but requires a
provider key and the `--enable-runtime-attacks` opt-in).

## Why this lives in the repo

Several of the hardening checks `secure-review-runtime` performs
(missing CSP, weak cookie attributes, sensitive paths) only produce
output when there is *something to find*. Pointing it at a clean
production app would report nothing. This stub guarantees the demo
finds real signal so first-time users see what the tool actually does.
