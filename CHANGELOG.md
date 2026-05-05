# Changelog

All notable changes to `secure-review-runtime` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased] — 1.1.1

In progress on `feat/v1.1.1-polish`. Polish + bug-fix round following the
post-merge validation pass on v1.1.0.

### Fixed
- **README install command was broken** — claimed
  `npm install secure-review-runtime` but the package is GitHub-only by
  design. Split into two lines: `secure-review` from npm, this package
  from `github:sstaempfli/secure-review-runtime#v1.1.1`. Added a short
  rationale paragraph.

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
