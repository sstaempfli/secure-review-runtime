# Changelog

All notable changes to `secure-review-runtime` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

Runtime browser crawling — addresses the May-13 review feedback that a
`curl`/`fetch` crawler cannot get past a login page or render a JS app.

### Added
- **`--playwright` is now reachable from the GitHub Action and
  `pr-runtime`**, not just the local `attack-ai` CLI. New `playwright`
  Action input, `--playwright` flag on `pr-runtime`, and
  `INPUT_PLAYWRIGHT` → `--playwright` argv-shim translation (with test
  coverage for truthy/falsy/unset).
- **`playwright` declared as an optional peer dependency**
  (`peerDependenciesMeta.playwright.optional`) so installs never pull
  Chromium implicitly, and tooling knows the supported version range.
- **README: "Crawling past login" + "Limitations & roadmap" sections** —
  documents the `--playwright` + `--browser-login-script` flow and
  frames the `curl` → real-browser → agentic progression honestly
  (Playwright MCP cited as emerging prior art).
- **`examples/vulnerable-target` gained a JS-rendered + login-gated
  section** (`/app`, `/api/nav`, `/dashboard`, `/admin/export`) plus a
  working `login.mjs` browser-login script and an `attack-skill.md`, so
  the Playwright advantage is demonstrable end-to-end, not just
  described. Verified with real runs: the fetch crawler sees an empty
  shell; `--playwright` captures the `/api/nav` XHR; without the login
  script the crawl is bounced to `/login`; with `./login.mjs` it
  reaches `/dashboard` and `/admin/export`. The weak demo cookie is
  scoped to `/` so it cannot clobber the injected session mid-crawl;
  the original 9 deterministic `attack` findings on `/` are unchanged.

### Fixed
- **`npm run typecheck` was broken** by the new `playwright-crawler.ts`:
  `tsc` tried to resolve the optional, undeclared `playwright` module.
  The dynamic `import()` specifier is now held in a variable so the
  type-checker leaves the optional peer alone; runtime behaviour
  (clear install hint when absent) is unchanged.

## [1.1.1] — 2026-05-06

(Same campaign as the original 2026-05-05 changelog below; absorbed three
follow-up fixes from Google's Gemini Code Assist review on PR #2 before
the merge.)

### Changed (additional, after Gemini review)
- **`SECURE_REVIEW_FORWARD_` prefix is now stripped before the env var
  reaches the child.** Previously the prefix flowed through verbatim
  (`SECURE_REVIEW_FORWARD_NUCLEI_TEMPLATES_DIR=/x` reached `nuclei` as
  `SECURE_REVIEW_FORWARD_NUCLEI_TEMPLATES_DIR`, which `nuclei` ignored).
  The escape hatch is now actually useful: the spawned tool sees the
  real env var name (`NUCLEI_TEMPLATES_DIR=/x`). Forwarded vars also
  override the regular allowlist on conflict (explicit user opt-in
  beats the default).
- **`DOCKER_` is now a prefix, not an explicit list.** Replaces the
  five enumerated keys (`DOCKER_HOST`, `DOCKER_CONFIG`,
  `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `DOCKER_BUILDKIT`) so future
  / less-common docker env vars (`DOCKER_DEFAULT_PLATFORM`,
  `DOCKER_SCAN_*`, etc.) flow through to `docker run` without future
  maintenance.
- **`runBrowserLoginScript` now warns when the script's `headers`
  payload contains non-string values.** Matches the new
  `parseAuthHeadersJson` behaviour from the same release. Previously
  silent.

## [1.1.1] — 2026-05-05

Polish + bug-fix round following the post-merge validation pass on v1.1.0.
GitHub-only release (this package is not published on npm by design); pin
to `github:sstaempfli/secure-review-runtime#v1.1.1`.

### Changed (breaking)
- **`action.yml` default `mode` flipped from `attack-ai` → `attack`.**
  `attack-ai` requires a provider API key and incurs a per-run cost; it
  is no longer the default for the GitHub Action. Workflows that
  relied on the previous default and want LLM-planned probing must
  now set `mode: attack-ai` explicitly. Aligns with the README's
  "use `attack` on every PR" guidance.

### Added
- **`gates.max_cost_usd` is now enforced** mid-run as a post-planning
  circuit breaker for `attack-ai`. Previously `--max-cost-usd` mutated
  the field but nothing consulted it. Setting `max_cost_usd: 0`
  disables the cap.
- **Schema guard at startup** (`assertRuntimeConfigShape`) — fails fast
  with a clear "secure-review schema drifted" message if the peer
  dependency removes or wrong-types `dynamic.enabled`,
  `dynamic.target_url`, or `gates.max_cost_usd`.
- **Working `examples/vulnerable-target/.secure-review.yml`** so the
  README quickstart works zero-flag (it crashed before with `ENOENT`).
- **CI workflow** already shipped in v1.1.0 unchanged.

### Fixed
- **README install command was broken** — claimed
  `npm install secure-review-runtime` but the package is GitHub-only by
  design. Split into two lines: `secure-review` from npm, this package
  from `github:sstaempfli/secure-review-runtime#v1.1.1`. Added a short
  rationale paragraph and dropped the fabricated "$0.05–$0.50" cost
  claim that contradicted action.yml's $20 default.
- **External-scanner env-leak (closes the v1.1.0 follow-up).** Both
  `runNucleiExport` and `runZapBaselineDocker` now pass an allowlisted
  env (`buildScannerEnv`) to `spawnSync` instead of the full
  `process.env`. The browser-login allowlist was extracted to a shared
  module `src/internal/env-allowlist.ts`; both profiles share a base
  set (POSIX, locale, proxy, NODE_EXTRA_CA_CERTS) plus tooling-specific
  additions (Playwright/Puppeteer for browser-login, Docker/Nuclei for
  scanners) and the universal `SECURE_REVIEW_FORWARD_*` opt-in.
- **Markdown injection in PR comments.** Reporter output and the ZAP
  stderr appendix now route every interpolated finding field through
  `escapeInlineCode` / `escapeTableCell` / `escapeFencedBlock` /
  `escapeBodyText` / `escapeHeading`. Backticks, triple-backticks,
  pipes, newlines, and `</details>` tags can no longer break the
  table layout, escape an inline-code span, or close an enclosing
  `<details>` block early.
- **`parseAuthHeadersJson` now warns on every silent failure** —
  malformed JSON, non-object root, non-string values. Previously the
  function returned `undefined` with no log and probes ran
  unauthenticated.
- **`RequestBudget` clamps invalid configuration** — `rateLimitPerSecond`
  to `Math.max(0.1, value)` (no more divide-by-zero `Infinity`),
  `maxRequests` to `Math.max(1, floor(value))` (no more
  zero-budget lockout).
- **`runBrowserLoginScript` validates the script path** — trims
  whitespace, `statSync`s the resolved path, and rejects directories /
  sockets / FIFOs / non-existent symlink targets with messages that
  name the offending type instead of the previous opaque
  `execFileSync` crash. The JSON payload schema is also tightened:
  arrays and `null` are explicitly rejected as the top-level value
  and as the `headers` property.
- **Gate-skip message is paste-ready.** When the opt-in gate refuses
  to fire, the warning now includes a literal `dynamic:\n  enabled: true`
  YAML snippet you can copy directly into `.secure-review.yml`,
  alongside the CLI-flag and Action-input alternatives.
- **Renamed "Layer-4" → "runtime HTTP"** throughout the README,
  CHANGELOG, action.yml, and CLI command descriptions. The probes are
  application-layer (Layer-7), not transport-layer.

### Tests
- Test suite grew from 28 cases to 97 across 11 files. New coverage:
  scanner env profile, markdown escape (incl. hostile-field snapshot),
  auth-headers JSON parse warnings, request budget clamps, schema
  guard, browser-login path validation + JSON payload, GitHub Actions
  argv-shim integration, and an in-process E2E run of `runAttackMode`
  against a deliberately-vulnerable stub server.

### Internal
- `RequestBudget` and `buildGhActionArgv` are now exported (purely for
  testability; not part of the public-facing API contract).

## [1.1.0] — 2026-05-04 (GitHub release on `master`, tag pending)

### Added
- **Opt-in gate for runtime attack modes.** `attack` / `attack-ai` modes
  now require an explicit opt-in: CLI flag `--enable-runtime-attacks`,
  GitHub Action input `enable-runtime-attacks: true`, OR
  `dynamic.enabled: true` in the config. Without one of these, runtime
  modes log a warning and skip cleanly. Closes the auto-fire risk where
  a stale `dynamic.target_url` could silently send probes to the wrong
  host on every PR.
- **`examples/vulnerable-target/`** — a 50-line, zero-dependency Node
  HTTP server with deliberate flaws so the README quickstart produces
  real findings out of the box.
- **`.github/workflows/ci.yml`** — three jobs: test (Node 20 / 22
  matrix), typecheck, and build-freshness (rebuilds `dist/` and
  `dist-action/` and fails on drift).
- **`prepublishOnly` script** in `package.json` — guarantees that any
  `npm publish` rebuilds both `dist/` (TypeScript output + `.d.ts`) and
  `dist-action/` (single-file GitHub Action bundle) from the current
  source.

### Changed (breaking — please read)
- **Browser-login scripts now run with a strict env allowlist.**
  `runBrowserLoginScript` previously inherited the full `process.env`
  when spawning user-supplied login scripts, leaking provider API keys,
  `GITHUB_TOKEN`, `AWS_*`, and other secrets to the script. The new
  allowlist forwards POSIX basics, locale/timezone, browser-automation
  knobs (`PLAYWRIGHT_*`, `PUPPETEER_*`, `CHROME_*`, `DISPLAY`,
  `XAUTHORITY`, `XDG_*`), proxy config, `NODE_EXTRA_CA_CERTS`, and the
  explicit user opt-in prefix `SECURE_REVIEW_FORWARD_*`. See README
  "Browser-login scripts run in a stripped environment" section. If
  your script depended on a non-standard env var, prefix it with
  `SECURE_REVIEW_FORWARD_` to opt in.
- **Runtime attack modes default to "skip" instead of "fire".** Because
  this is opt-in, configs that previously fired probes via
  `dynamic.target_url` alone now log a warning and skip until
  `dynamic.enabled: true` (or one of the other opt-in routes) is set.

### Security
- Closes credential-leak vector to user-supplied browser-login scripts
  (CVE-class severity in CI: an attacker-controlled login script
  receives the full GitHub Actions secret payload).
- Closes silent auto-fire of LLM-planned probes from a stale
  `dynamic.target_url`.

### Build
- `dist/` is no longer gitignored; types (`dist/index.d.ts`) ship with
  the repo as well as the npm tarball.
- `prepublishOnly` ensures published packages always carry a fresh
  build of both `dist/` and `dist-action/`.

### Internal
- `.gitignore` now ignores `.env` / `.env.*` (with `!.env.example`
  preserved). The CLI loads `.env` via `dotenv`, so a user committing
  the working tree previously would leak local secrets.

### Notes
- `src/pentest/external-scanners.ts` (the ZAP/Nuclei wrappers) still
  spawns external tools without an env allowlist. Different threat
  profile (running our own binaries, not user-supplied scripts), but
  worth tightening — tracked for a follow-up patch.
