import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildAllowlistedEnv, runBrowserLoginScript } from '../src/pentest/browser-login.js';

const tmpDirs: string[] = [];

afterEach(() => {
  vi.unstubAllEnvs();
  while (tmpDirs.length) {
    const d = tmpDirs.pop()!;
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

function makeProbeScript(): { scriptPath: string; cwd: string } {
  const cwd = mkdtempSync(join(tmpdir(), 'srrt-probe-'));
  tmpDirs.push(cwd);
  const scriptPath = join(cwd, 'probe.mjs');
  // The probe smuggles its env back as JSON-encoded object inside a header
  // value. The caller decodes the JSON and inspects the parsed object
  // directly — never doing substring containment on the raw string, which
  // would give a false pass when secret values contain JSON-escaped
  // characters (quotes, backslashes).
  writeFileSync(
    scriptPath,
    `const env = { ...process.env };\n` +
      `console.log(JSON.stringify({ headers: { 'X-Env-Snapshot': JSON.stringify(env) } }));\n`,
  );
  return { scriptPath, cwd };
}

describe('buildAllowlistedEnv — unit', () => {
  it('drops provider API keys, GH/AWS tokens, DB URLs, and arbitrary secrets', () => {
    const allow = buildAllowlistedEnv({
      PATH: '/usr/bin',
      HOME: '/Users/alfonso',
      ANTHROPIC_API_KEY: 'sk-ant-secret',
      OPENAI_API_KEY: 'sk-openai-secret',
      GOOGLE_API_KEY: 'goog-secret',
      GEMINI_API_KEY: 'gem-secret',
      GH_TOKEN: 'ghp_secret',
      GITHUB_TOKEN: 'ghp_secret2',
      AWS_ACCESS_KEY_ID: 'AKIA...',
      AWS_SECRET_ACCESS_KEY: 'aws-secret',
      DATABASE_URL: 'postgres://u:p@h/db',
      MY_PASSWORD: 'hunter2',
    });
    expect(allow.PATH).toBe('/usr/bin');
    expect(allow.HOME).toBe('/Users/alfonso');
    expect(allow.ANTHROPIC_API_KEY).toBeUndefined();
    expect(allow.OPENAI_API_KEY).toBeUndefined();
    expect(allow.GOOGLE_API_KEY).toBeUndefined();
    expect(allow.GEMINI_API_KEY).toBeUndefined();
    expect(allow.GH_TOKEN).toBeUndefined();
    expect(allow.GITHUB_TOKEN).toBeUndefined();
    expect(allow.AWS_ACCESS_KEY_ID).toBeUndefined();
    expect(allow.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(allow.DATABASE_URL).toBeUndefined();
    expect(allow.MY_PASSWORD).toBeUndefined();
  });

  it('blocks NODE_OPTIONS (code-injection vector via --require/--import)', () => {
    const allow = buildAllowlistedEnv({
      NODE_OPTIONS: '--require /tmp/evil.js',
      NODE_ENV: 'development',
    });
    expect(allow.NODE_OPTIONS).toBeUndefined();
    expect(allow.NODE_ENV).toBe('development');
  });

  it('blocks NODE_PATH (module-shadowing vector)', () => {
    const allow = buildAllowlistedEnv({ NODE_PATH: '/tmp/evil/lib' });
    expect(allow.NODE_PATH).toBeUndefined();
  });

  it('blocks NODE_TLS_REJECT_UNAUTHORIZED (silent TLS bypass)', () => {
    const allow = buildAllowlistedEnv({ NODE_TLS_REJECT_UNAUTHORIZED: '0' });
    expect(allow.NODE_TLS_REJECT_UNAUTHORIZED).toBeUndefined();
  });

  it('blocks SSH_AUTH_SOCK (would forward the SSH agent to a third-party script)', () => {
    const allow = buildAllowlistedEnv({ SSH_AUTH_SOCK: '/tmp/ssh-agent.sock' });
    expect(allow.SSH_AUTH_SOCK).toBeUndefined();
  });

  it('forwards Playwright/Puppeteer/Chrome env (browser automation needs it)', () => {
    const allow = buildAllowlistedEnv({
      PLAYWRIGHT_BROWSERS_PATH: '/opt/pw',
      PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1',
      PUPPETEER_EXECUTABLE_PATH: '/usr/bin/chromium',
      PUPPETEER_CACHE_DIR: '/var/cache/pp',
      BROWSER: 'chromium',
      CHROME_PATH: '/usr/bin/chrome',
      CHROME_BIN: '/usr/bin/chrome',
      DISPLAY: ':0',
      XAUTHORITY: '/run/user/1000/gdm/Xauthority',
      WAYLAND_DISPLAY: 'wayland-0',
    });
    expect(allow.PLAYWRIGHT_BROWSERS_PATH).toBe('/opt/pw');
    expect(allow.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD).toBe('1');
    expect(allow.PUPPETEER_EXECUTABLE_PATH).toBe('/usr/bin/chromium');
    expect(allow.PUPPETEER_CACHE_DIR).toBe('/var/cache/pp');
    expect(allow.BROWSER).toBe('chromium');
    expect(allow.CHROME_PATH).toBe('/usr/bin/chrome');
    expect(allow.CHROME_BIN).toBe('/usr/bin/chrome');
    expect(allow.DISPLAY).toBe(':0');
    expect(allow.XAUTHORITY).toBe('/run/user/1000/gdm/Xauthority');
    expect(allow.WAYLAND_DISPLAY).toBe('wayland-0');
  });

  it('forwards SECURE_REVIEW_FORWARD_* opt-in escape hatch (and only that prefix)', () => {
    const allow = buildAllowlistedEnv({
      SECURE_REVIEW_FORWARD_TOKEN: 'opt-in',
      SECURE_REVIEW_FORWARD_FOO: 'bar',
      SECURE_REVIEW_OTHER: 'should-not-flow',
      SECURE_REVIEW_AUTH_LEGACY: 'should-not-flow',
    });
    expect(allow.SECURE_REVIEW_FORWARD_TOKEN).toBe('opt-in');
    expect(allow.SECURE_REVIEW_FORWARD_FOO).toBe('bar');
    expect(allow.SECURE_REVIEW_OTHER).toBeUndefined();
    expect(allow.SECURE_REVIEW_AUTH_LEGACY).toBeUndefined();
  });

  it('drops keys with undefined values', () => {
    const source: NodeJS.ProcessEnv = { PATH: '/usr/bin', HOME: undefined };
    const allow = buildAllowlistedEnv(source);
    expect(allow.PATH).toBe('/usr/bin');
    expect(Object.prototype.hasOwnProperty.call(allow, 'HOME')).toBe(false);
  });

  it('forwards proxy env in both case forms', () => {
    const allow = buildAllowlistedEnv({
      HTTP_PROXY: 'http://upper:1',
      HTTPS_PROXY: 'http://upper:2',
      NO_PROXY: 'localhost',
      http_proxy: 'http://lower:1',
      https_proxy: 'http://lower:2',
      no_proxy: '127.0.0.1',
    });
    expect(allow.HTTP_PROXY).toBe('http://upper:1');
    expect(allow.HTTPS_PROXY).toBe('http://upper:2');
    expect(allow.NO_PROXY).toBe('localhost');
    expect(allow.http_proxy).toBe('http://lower:1');
    expect(allow.https_proxy).toBe('http://lower:2');
    expect(allow.no_proxy).toBe('127.0.0.1');
  });

  it('snapshot: forwards exactly the documented keys (drift guard)', () => {
    // Probe with one of every allowlisted key + a representative blocked key
    const probe: NodeJS.ProcessEnv = {
      PATH: 'a',
      HOME: 'a',
      USER: 'a',
      LOGNAME: 'a',
      SHELL: 'a',
      LANG: 'a',
      LC_ALL: 'a',
      LC_CTYPE: 'a',
      TZ: 'a',
      TMPDIR: 'a',
      TEMP: 'a',
      TMP: 'a',
      NODE_ENV: 'a',
      BROWSER: 'a',
      CHROME_PATH: 'a',
      CHROME_BIN: 'a',
      CHROMIUM_FLAGS: 'a',
      DISPLAY: 'a',
      XAUTHORITY: 'a',
      WAYLAND_DISPLAY: 'a',
      XDG_CONFIG_HOME: 'a',
      XDG_CACHE_HOME: 'a',
      XDG_DATA_HOME: 'a',
      XDG_RUNTIME_DIR: 'a',
      HTTP_PROXY: 'a',
      HTTPS_PROXY: 'a',
      NO_PROXY: 'a',
      http_proxy: 'a',
      https_proxy: 'a',
      no_proxy: 'a',
      NODE_EXTRA_CA_CERTS: 'a',
      // Prefix-matched
      PLAYWRIGHT_BROWSERS_PATH: 'a',
      PUPPETEER_CACHE_DIR: 'a',
      SECURE_REVIEW_FORWARD_FOO: 'a',
      // Blocked
      ANTHROPIC_API_KEY: 'BOOM',
      NODE_OPTIONS: 'BOOM',
      NODE_PATH: 'BOOM',
      NODE_TLS_REJECT_UNAUTHORIZED: 'BOOM',
      SSH_AUTH_SOCK: 'BOOM',
    };
    const allow = buildAllowlistedEnv(probe);
    expect(Object.keys(allow).sort()).toMatchInlineSnapshot(`
      [
        "BROWSER",
        "CHROME_BIN",
        "CHROME_PATH",
        "CHROMIUM_FLAGS",
        "DISPLAY",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "NODE_ENV",
        "NODE_EXTRA_CA_CERTS",
        "NO_PROXY",
        "PATH",
        "PLAYWRIGHT_BROWSERS_PATH",
        "PUPPETEER_CACHE_DIR",
        "SECURE_REVIEW_FORWARD_FOO",
        "SHELL",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "http_proxy",
        "https_proxy",
        "no_proxy",
      ]
    `);
  });
});

describe('runBrowserLoginScript end-to-end env stripping', () => {
  it('does NOT leak provider API keys or GH tokens to the spawned script', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-ant-canary-value-xyz');
    vi.stubEnv('OPENAI_API_KEY', 'sk-openai-canary-value-xyz');
    vi.stubEnv('GH_TOKEN', 'ghp_canary_xyz');
    vi.stubEnv('AWS_SECRET_ACCESS_KEY', 'aws-canary-xyz');

    const { scriptPath, cwd } = makeProbeScript();
    const result = runBrowserLoginScript(scriptPath, cwd);
    const snapshotStr = result.headers['X-Env-Snapshot'];
    expect(typeof snapshotStr).toBe('string');
    const snapshot = JSON.parse(snapshotStr) as Record<string, string>;
    // Inspect the parsed object — substring search on the JSON string is
    // unsafe (JSON.stringify escapes quotes/backslashes, so a secret with a
    // quote in it would not appear literally and a substring assertion
    // would give a false pass).
    expect(snapshot).not.toHaveProperty('ANTHROPIC_API_KEY');
    expect(snapshot).not.toHaveProperty('OPENAI_API_KEY');
    expect(snapshot).not.toHaveProperty('GH_TOKEN');
    expect(snapshot).not.toHaveProperty('AWS_SECRET_ACCESS_KEY');
    // Sanity: the canary values themselves must be absent from any value.
    for (const value of Object.values(snapshot)) {
      expect(value).not.toContain('sk-ant-canary-value-xyz');
      expect(value).not.toContain('sk-openai-canary-value-xyz');
      expect(value).not.toContain('ghp_canary_xyz');
      expect(value).not.toContain('aws-canary-xyz');
    }
  });

  it('forwards SECURE_REVIEW_FORWARD_* and PATH to the script', () => {
    vi.stubEnv('SECURE_REVIEW_FORWARD_FOO', 'forward-me');
    const { scriptPath, cwd } = makeProbeScript();
    const result = runBrowserLoginScript(scriptPath, cwd);
    const snapshot = JSON.parse(result.headers['X-Env-Snapshot']) as Record<string, string>;
    expect(snapshot.SECURE_REVIEW_FORWARD_FOO).toBe('forward-me');
    expect(typeof snapshot.PATH, 'PATH must flow so child can find binaries').toBe('string');
  });
});
