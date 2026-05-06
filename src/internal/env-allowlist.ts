/**
 * Centralised env-stripping allowlists for every subprocess this package
 * spawns.
 *
 * Threat model: spawned subprocesses (user-supplied browser-login scripts
 * AND tools we invoke ourselves like `nuclei` or `docker run`) must not
 * inherit secrets from the parent environment. The full `process.env` of
 * a CI runner contains every repo secret (provider API keys,
 * `GITHUB_TOKEN`, `AWS_*`, etc.). Any compromised or compromised-template
 * scanner — or a misbehaving login script — would otherwise see them all.
 *
 * Why two profiles?
 * - `buildAllowlistedEnv` (used by `runBrowserLoginScript`) needs
 *   browser-automation knobs (Playwright/Puppeteer/Chromium config,
 *   `DISPLAY`, `XAUTHORITY`, `XDG_*`).
 * - `buildScannerEnv` (used by `runNucleiExport` and
 *   `runZapBaselineDocker`) needs Docker socket/config keys and Nuclei
 *   tooling vars but does not need GUI-related ones.
 *
 * Both share a common base of POSIX identity, locale, temp dirs, proxy
 * config, and `NODE_EXTRA_CA_CERTS` (corporate MITM CA — additive only,
 * NOT a TLS-verification bypass like `NODE_TLS_REJECT_UNAUTHORIZED`).
 *
 * Both honour the universal opt-in escape hatch: any env key prefixed
 * with `SECURE_REVIEW_FORWARD_` flows through, **with the prefix
 * stripped before reaching the child**. Setting
 * `SECURE_REVIEW_FORWARD_NUCLEI_TEMPLATES_DIR=/x` makes the spawned
 * scanner see `NUCLEI_TEMPLATES_DIR=/x` — the receiver tools recognise
 * their normal env var names, not our internal prefix. The forward
 * also takes precedence over the regular allowlist on conflict (an
 * explicit user opt-in beats a default).
 *
 * Deliberately blocked everywhere:
 * - Provider API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …) and
 *   any other `*_TOKEN` / `*_KEY` / `*_SECRET` / `*_PASSWORD`.
 * - `NODE_OPTIONS` (code injection via `--require` / `--import`).
 * - `NODE_PATH` (module shadowing).
 * - `NODE_TLS_REJECT_UNAUTHORIZED` (TLS-bypass foot-gun).
 * - `SSH_AUTH_SOCK` (would forward the SSH agent).
 * - `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_*`, `AZURE_*`, `GCP_*`, `DATABASE_URL`.
 */

/** Minimal POSIX / locale / proxy / CA-cert allowlist shared everywhere. */
const BASE_ALLOWLIST_KEYS: ReadonlySet<string> = new Set([
  // POSIX identity and shell
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'SHELL',
  // Locale and timezone
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  // Temp directories
  'TMPDIR',
  'TEMP',
  'TMP',
  // Safe Node tunable (NODE_OPTIONS / NODE_PATH / NODE_TLS_REJECT_UNAUTHORIZED
  // are intentionally NOT here — see file-level comment).
  'NODE_ENV',
  // Corporate proxy config (uppercase + lowercase forms)
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  // Additive CA bundle for corporate MITM proxies (NOT a TLS bypass).
  'NODE_EXTRA_CA_CERTS',
]);

/** Browser-automation tooling — Playwright / Puppeteer / Chromium / GUI. */
const BROWSER_AUTOMATION_KEYS: ReadonlySet<string> = new Set([
  'BROWSER',
  'CHROME_PATH',
  'CHROME_BIN',
  'CHROMIUM_FLAGS',
  'DISPLAY',
  'XAUTHORITY',
  'WAYLAND_DISPLAY',
  'XDG_CONFIG_HOME',
  'XDG_CACHE_HOME',
  'XDG_DATA_HOME',
  'XDG_RUNTIME_DIR',
]);
const BROWSER_AUTOMATION_PREFIXES: readonly string[] = ['PLAYWRIGHT_', 'PUPPETEER_'];

/** External scanners — Docker socket/config + Nuclei templates. */
const SCANNER_KEYS: ReadonlySet<string> = new Set();
// Docker uses a wide family of env vars (DOCKER_HOST, DOCKER_CONFIG,
// DOCKER_CERT_PATH, DOCKER_TLS_VERIFY, DOCKER_BUILDKIT, DOCKER_SCAN_*,
// DOCKER_DEFAULT_PLATFORM, etc.). Forward the whole prefix rather than
// chasing each key individually as the docker CLI evolves.
// Nuclei similarly uses NUCLEI_TEMPLATES_DIR, NUCLEI_CONFIG, etc.
const SCANNER_PREFIXES: readonly string[] = ['DOCKER_', 'NUCLEI_'];

/** Universal opt-in escape hatch. Honour everywhere. */
const FORWARD_PREFIX = 'SECURE_REVIEW_FORWARD_';

function filterEnv(
  source: NodeJS.ProcessEnv,
  keys: ReadonlySet<string>,
  prefixes: readonly string[],
): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};

  // First pass: regular allowlist (explicit keys + tooling prefixes).
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (keys.has(key) || prefixes.some((p) => key.startsWith(p))) {
      out[key] = value;
    }
  }

  // Second pass: SECURE_REVIEW_FORWARD_* opt-in. Strip the prefix so the
  // child sees the un-prefixed name (which is what receiver tools recognise),
  // and let the forward override anything from the first pass on conflict
  // (an explicit user opt-in beats the default allowlist value).
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (!key.startsWith(FORWARD_PREFIX)) continue;
    const stripped = key.slice(FORWARD_PREFIX.length);
    if (!stripped) continue; // ignore the bare prefix with no suffix
    out[stripped] = value;
  }

  return out;
}

/** Allowlisted env for user-supplied browser-login scripts. */
export function buildAllowlistedEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const keys = new Set<string>([...BASE_ALLOWLIST_KEYS, ...BROWSER_AUTOMATION_KEYS]);
  return filterEnv(source, keys, BROWSER_AUTOMATION_PREFIXES);
}

/** Allowlisted env for external scanners (`nuclei`, `docker run …`). */
export function buildScannerEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const keys = new Set<string>([...BASE_ALLOWLIST_KEYS, ...SCANNER_KEYS]);
  return filterEnv(source, keys, SCANNER_PREFIXES);
}
