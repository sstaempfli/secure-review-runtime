# vulnerable-target — quickstart demo

A small, zero-dependency HTTP server with deliberate security flaws so
you can see what `secure-review-runtime attack` reports against a real
target without hosting one — plus a JS-rendered, login-gated section
that demonstrates why `attack-ai --playwright` exists.

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

## Why `--playwright` — the fetch crawler is blind here

The server also serves a single-page-app section whose links, form, and
API call are created **by JavaScript at runtime**, plus a login-gated
page:

| Route | Behaviour |
|---|---|
| `GET /app` | Empty `<div id="root">` shell. JS fetches `/api/nav` and builds the nav links + a search form in the DOM. The raw HTML has no `href`/`<form>` at all. |
| `GET /api/nav` | JSON the shell calls via `fetch()` at runtime — an API endpoint only a real browser ever requests. |
| `GET /dashboard` | `302 → /login` unless a real `session=` cookie is presented (the weak demo cookie does **not** count). With one, it exposes an `/admin/export?account=1001` link. |

Run it from **this directory** (it has its own `.secure-review.yml`,
the `attack-skill.md` skill, and a demo `login.mjs`). `attack-ai` needs
a provider key — the examples below use a cheap OpenAI model; swap
`--attack-provider`/`--attack-model` for whatever key you have:

```sh
node server.js   # terminal 1

# terminal 2 — Playwright crawler WITHOUT auth: the /dashboard link is
# discovered but the crawler is bounced to /login.
npx secure-review-runtime attack-ai . \
  --target-url http://localhost:3000/app --playwright \
  --attack-provider openai --attack-model gpt-4o-mini \
  --attack-skill attack-skill.md --enable-runtime-attacks

# WITH the browser-login script: the session cookie is injected into the
# browser context and the crawl reaches /dashboard and /admin/export.
npx secure-review-runtime attack-ai . \
  --target-url http://localhost:3000/app --playwright \
  --browser-login-script ./login.mjs \
  --attack-provider openai --attack-model gpt-4o-mini \
  --attack-skill attack-skill.md --enable-runtime-attacks
```

Observed difference in the crawl surface handed to the LLM planner
(verified runs, not illustrative):

- **fetch** `/app` → `links: []`, `forms: 0`, no API endpoints — blind.
- **Playwright** `/app` → `links: [/profile, /dashboard]`, `forms: 1`,
  `apiEndpoints: [/api/nav?role=guest]`.
- **Playwright, no login script** → crawls `/app → /profile → /login`
  (the `/dashboard` gate correctly blocks it).
- **Playwright + `./login.mjs`** → `Applied 1 auth cookie to browser
  context`, then crawls `/app → /profile → /dashboard →
  /admin/export?account=1001`.

This is the concrete answer to "how would you attack an API behind a JS
frontend or a login?" — those endpoints don't exist for a curl-style
crawler.

## Why this lives in the repo

Several of the hardening checks `secure-review-runtime` performs
(missing CSP, weak cookie attributes, sensitive paths) only produce
output when there is *something to find*. Pointing it at a clean
production app would report nothing. This stub guarantees the demo
finds real signal so first-time users see what the tool actually does.
