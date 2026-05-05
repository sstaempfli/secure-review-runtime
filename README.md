# secure-review-runtime

> Layer-4 runtime security probes for live HTTP services. Deterministic
> baseline checks, optional LLM-planned same-origin probing, and OWASP
> ZAP / Nuclei wrappers — usable as a CLI, locally, or as a GitHub
> Action that comments on every PR.

**Repo:** [sstaempfli/secure-review-runtime](https://github.com/sstaempfli/secure-review-runtime)
· **Static peer (npm):** [secure-review](https://github.com/fonCki/secure-review).

## What it does (60 seconds)

`secure-review-runtime` complements [`secure-review`](https://github.com/fonCki/secure-review)
(static analysis + multi-model PR review) with **runtime** checks against
a live URL:

- **`attack`** — fast, deterministic probes that report missing security
  headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), weak
  cookie attributes, permissive CORS, and exposed sensitive paths. Pure
  HTTP, no LLM, no extra binaries. **Use this on every PR.**
- **`attack-ai`** — an LLM crawls a small same-origin sample and plans
  targeted probes (reflected XSS, IDOR-style URL mutation, etc.) with a
  capped request budget. Costs cents per run, requires a provider key.
  **Use this for explicit security passes, not on every PR.**
- **`pr-runtime`** — wraps either of the above as a GitHub Action that
  posts a Markdown comment on a PR.
- **External scanners** — optional pluggable wrappers around OWASP ZAP
  (`zap-baseline`, requires Docker) and Nuclei (requires the `nuclei`
  binary).

Use `secure-review` alone for source-only review (`review`, `fix`,
`scan`, `pr`). Use this package when you have a reachable base URL.

## Install

`secure-review-runtime` is **GitHub-only by design** — it isn't published
on the npm registry. The static peer (`secure-review`) IS on npm.

```bash
# Static peer (npm)
npm install --save-dev secure-review

# This package (GitHub — pin to a tag)
npm install --save-dev github:sstaempfli/secure-review-runtime#v1.1.1
```

Why GitHub-only? The runtime path probes live targets and we'd rather
ask users to pin a specific tag than risk a broad npm rollout while the
threat model is still evolving. The static peer is stable and ships
through the registry as usual. As a GitHub-installed package, the
`prepare` script auto-builds `dist/` on first install — Node 20+ is
required.

## Quickstart (60 seconds)

The repo ships a deliberately-vulnerable demo server **and** a working
`.secure-review.yml` next to it, so the quickstart runs without you
having to author a config first.

```bash
# Terminal 1 — start the demo target on :3000
cd examples/vulnerable-target/
node server.js
# vulnerable-target listening on http://localhost:3000

# Terminal 2 — run the deterministic `attack` mode against it
cd examples/vulnerable-target/
npx secure-review-runtime attack
# → 9 findings: missing CSP/HSTS/X-Frame-Options, weak Set-Cookie,
#   permissive CORS, exposed /.env, info-disclosure Server header
```

(`attack` reads `./.secure-review.yml`, which sets `dynamic.enabled: true`
and `target_url: http://localhost:3000`. No CLI flags needed for the
demo; pass `--target-url` and `--output-dir` to override.) The Markdown
report and JSON findings land under `./reports/` next to the config.

## Modes — when to use which

| Mode         | Cost                 | Speed      | LLM keys?    | When to use                                                                 |
|--------------|----------------------|------------|--------------|-----------------------------------------------------------------------------|
| `attack`     | $0                   | seconds    | No           | Every PR. Catches the OWASP-easy stuff: headers, cookies, CORS, sensitive paths. |
| `attack-ai`  | depends on planner† | 30–120s    | Yes          | Periodic security passes. LLM-planned probes for XSS / IDOR / behavioural bugs. |
| `pr-runtime` | as above             | as above   | as above     | The GitHub Action wrapper around `attack` / `attack-ai`. Posts a PR comment. |
| `attack` + `--pentest-scanners zap-baseline,nuclei` | $0 (binaries are local) | 5–15 min | No | Pre-release / nightly. Deeper coverage from external scanners. |

† `attack-ai` runs **one** LLM-planning call per run (capped at 3000
output tokens by default) plus deterministic HTTP probes that don't
hit the LLM. Cost depends on your provider and chosen model; the
runtime reports the actual cost as `totalCostUSD` in the JSON
findings file. Set `gates.max_cost_usd` in your config (or pass
`--max-cost-usd` / the `max-cost-usd` Action input — default 20) as a
post-planning circuit breaker that aborts if the planner exceeded
that budget.

## Security model — please read

### `attack-ai` requires explicit opt-in

The Action defaults `mode: attack-ai`. Combined with a stale or
copy-pasted `dynamic.target_url` in `.secure-review.yml`, that would
silently fire LLM-planned probes against the wrong host on every PR.

To prevent this, runtime attack modes only run when **at least one**
of the following is true:

1. CLI flag `--enable-runtime-attacks` is passed
2. GitHub Action input `enable-runtime-attacks: true` is set
3. `dynamic.enabled: true` is set in the config

Otherwise the mode logs a warning and exits cleanly without sending any
requests.

```yaml
# .secure-review.yml
dynamic:
  enabled: true                           # opt-in to runtime probing
  target_url: http://staging.example.com  # never points at prod or a third-party
```

```yaml
# .github/workflows/security.yml
- uses: sstaempfli/secure-review-runtime@v1
  with:
    mode: attack-ai
    target-url: ${{ secrets.STAGING_URL }}
    enable-runtime-attacks: true          # explicit per-workflow opt-in
```

### Browser-login scripts run in a stripped environment

If you use `--browser-login-script` to drive a Playwright/Puppeteer
login flow that returns authenticated cookies, the script is spawned
with a **strict env allowlist**, not the full `process.env`. Without
this, every secret in your shell or CI environment (provider API keys,
`GITHUB_TOKEN`, `AWS_*`) would leak to a third-party script.

What flows through to the script:

- POSIX basics: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`
- Locale and timezone: `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`
- Temp dirs: `TMPDIR`, `TEMP`, `TMP`
- Browser knobs: `BROWSER`, `CHROME_PATH`, `CHROME_BIN`, `CHROMIUM_FLAGS`,
  `DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY`, `XDG_*`
- Proxy config: `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` (both case forms)
- Custom CA bundle: `NODE_EXTRA_CA_CERTS` (additive — does NOT disable TLS)
- Prefix-matched: `PLAYWRIGHT_*`, `PUPPETEER_*`, and the explicit
  user-opt-in `SECURE_REVIEW_FORWARD_*`
- Safe Node tunables: `NODE_ENV` only (intentionally NOT `NODE_OPTIONS`,
  `NODE_PATH`, or `NODE_TLS_REJECT_UNAUTHORIZED`)

If your login script genuinely needs an env var that's blocked, prefix
it with `SECURE_REVIEW_FORWARD_` to opt in:

```bash
SECURE_REVIEW_FORWARD_MY_TOKEN=xyz npx secure-review-runtime attack . \
    --target-url ... --browser-login-script ./login.mjs
```

## CLI

```bash
# Run all the docs above
npx secure-review-runtime --help
npx secure-review-runtime attack --help
npx secure-review-runtime attack-ai --help
```

## External scanners — closed environments

`zap-baseline` runs the official OWASP ZAP container via Docker, so the
host needs:

- `docker` on `PATH` and a running daemon
- network egress to `ghcr.io` to pull the ZAP image once
- the target URL reachable from inside the container (use
  `host.docker.internal` instead of `localhost` on Mac/Windows)

`nuclei` shells out to the `nuclei` binary (install from
[ProjectDiscovery](https://github.com/projectdiscovery/nuclei)). The
binary must be on `PATH`. Nuclei templates can be vendored locally for
fully air-gapped setups.

When neither is available, the wrappers degrade gracefully with a
`scanner unavailable` finding rather than crashing.

## GitHub Action

The repo ships a prebuilt `dist-action/` bundle that `action.yml` points
at. After changing `src/` or dependencies, run `npm run build:action`
and commit the updated bundle — CI verifies freshness on every PR.

## Peer dependency

Depends on **`secure-review` ≥ 1.x** (pinned in `package.json`). Shared
types, config loading, env helpers, and gate evaluation come from the
core library.

## Development

```bash
npm install
npm test            # vitest
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/
npm run build:action  # ncc → dist-action/ (the GH-Action bundle)
```

## License

MIT
