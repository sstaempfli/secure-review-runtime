import { describe, it, expect } from 'vitest';
import { buildAllowlistedEnv, buildScannerEnv } from '../src/internal/env-allowlist.js';

describe('buildScannerEnv (env passed to nuclei / docker)', () => {
  it('drops provider API keys, GH/AWS tokens, DB URLs', () => {
    const allow = buildScannerEnv({
      PATH: '/usr/bin',
      ANTHROPIC_API_KEY: 'sk-ant-secret',
      OPENAI_API_KEY: 'sk-openai-secret',
      GOOGLE_API_KEY: 'goog-secret',
      GH_TOKEN: 'ghp_secret',
      GITHUB_TOKEN: 'ghp_secret2',
      AWS_ACCESS_KEY_ID: 'AKIA...',
      AWS_SECRET_ACCESS_KEY: 'aws-secret',
      DATABASE_URL: 'postgres://u:p@h/db',
      AZURE_CLIENT_SECRET: 'azure-secret',
    });
    expect(allow.PATH).toBe('/usr/bin');
    expect(allow.ANTHROPIC_API_KEY).toBeUndefined();
    expect(allow.OPENAI_API_KEY).toBeUndefined();
    expect(allow.GOOGLE_API_KEY).toBeUndefined();
    expect(allow.GH_TOKEN).toBeUndefined();
    expect(allow.GITHUB_TOKEN).toBeUndefined();
    expect(allow.AWS_ACCESS_KEY_ID).toBeUndefined();
    expect(allow.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(allow.DATABASE_URL).toBeUndefined();
    expect(allow.AZURE_CLIENT_SECRET).toBeUndefined();
  });

  it('forwards the whole DOCKER_ family (prefix match — covers future docker CLI env vars)', () => {
    const allow = buildScannerEnv({
      DOCKER_HOST: 'tcp://daemon:2375',
      DOCKER_CONFIG: '/home/u/.docker',
      DOCKER_CERT_PATH: '/home/u/.docker/certs',
      DOCKER_TLS_VERIFY: '1',
      DOCKER_BUILDKIT: '1',
      DOCKER_DEFAULT_PLATFORM: 'linux/amd64', // newer docker CLI flag
      DOCKER_SCAN_SUGGEST: 'false', // docker scan plugin
    });
    expect(allow.DOCKER_HOST).toBe('tcp://daemon:2375');
    expect(allow.DOCKER_CONFIG).toBe('/home/u/.docker');
    expect(allow.DOCKER_CERT_PATH).toBe('/home/u/.docker/certs');
    expect(allow.DOCKER_TLS_VERIFY).toBe('1');
    expect(allow.DOCKER_BUILDKIT).toBe('1');
    // Forward-by-prefix means future / less-common docker env vars flow too.
    expect(allow.DOCKER_DEFAULT_PLATFORM).toBe('linux/amd64');
    expect(allow.DOCKER_SCAN_SUGGEST).toBe('false');
  });

  it('forwards NUCLEI_* prefix (template dirs, config paths)', () => {
    const allow = buildScannerEnv({
      NUCLEI_TEMPLATES_DIR: '/opt/nuclei/templates',
      NUCLEI_CONFIG: '/etc/nuclei.yml',
      NUCLEI_NON_PREFIX: 'matches',
    });
    expect(allow.NUCLEI_TEMPLATES_DIR).toBe('/opt/nuclei/templates');
    expect(allow.NUCLEI_CONFIG).toBe('/etc/nuclei.yml');
    expect(allow.NUCLEI_NON_PREFIX).toBe('matches');
  });

  it('does NOT forward browser-automation env (Playwright/Puppeteer/DISPLAY) — those are browser-login-only', () => {
    const allow = buildScannerEnv({
      PLAYWRIGHT_BROWSERS_PATH: '/opt/pw',
      PUPPETEER_CACHE_DIR: '/var/pp',
      DISPLAY: ':0',
      XAUTHORITY: '/run/user/1000/gdm/Xauthority',
      WAYLAND_DISPLAY: 'wayland-0',
      BROWSER: 'chromium',
      CHROME_PATH: '/usr/bin/chrome',
    });
    expect(allow.PLAYWRIGHT_BROWSERS_PATH).toBeUndefined();
    expect(allow.PUPPETEER_CACHE_DIR).toBeUndefined();
    expect(allow.DISPLAY).toBeUndefined();
    expect(allow.XAUTHORITY).toBeUndefined();
    expect(allow.WAYLAND_DISPLAY).toBeUndefined();
    expect(allow.BROWSER).toBeUndefined();
    expect(allow.CHROME_PATH).toBeUndefined();
  });

  it('blocks NODE_OPTIONS / NODE_PATH / NODE_TLS_REJECT_UNAUTHORIZED everywhere', () => {
    const allow = buildScannerEnv({
      NODE_OPTIONS: '--require /tmp/evil.js',
      NODE_PATH: '/tmp/evil/lib',
      NODE_TLS_REJECT_UNAUTHORIZED: '0',
      NODE_ENV: 'development',
    });
    expect(allow.NODE_OPTIONS).toBeUndefined();
    expect(allow.NODE_PATH).toBeUndefined();
    expect(allow.NODE_TLS_REJECT_UNAUTHORIZED).toBeUndefined();
    expect(allow.NODE_ENV).toBe('development');
  });

  it('blocks SSH_AUTH_SOCK', () => {
    const allow = buildScannerEnv({ SSH_AUTH_SOCK: '/tmp/ssh-agent.sock' });
    expect(allow.SSH_AUTH_SOCK).toBeUndefined();
  });

  it('strips the SECURE_REVIEW_FORWARD_ prefix on forward (so child sees the real env name)', () => {
    const allow = buildScannerEnv({
      SECURE_REVIEW_FORWARD_FOO: 'forward-me',
      SECURE_REVIEW_FORWARD_NUCLEI_TEMPLATES_DIR: '/opt/custom-templates',
      SECURE_REVIEW_OTHER: 'should-not-flow',
    });
    // Stripped — the spawned tool sees its real env var name, not our prefix.
    expect(allow.FOO).toBe('forward-me');
    expect(allow.NUCLEI_TEMPLATES_DIR).toBe('/opt/custom-templates');
    // Original prefixed name does NOT flow.
    expect(allow.SECURE_REVIEW_FORWARD_FOO).toBeUndefined();
    expect(allow.SECURE_REVIEW_FORWARD_NUCLEI_TEMPLATES_DIR).toBeUndefined();
    // Sibling-prefix non-FORWARD must also not flow.
    expect(allow.SECURE_REVIEW_OTHER).toBeUndefined();
  });

  it('FORWARD overrides the regular allowlist on conflict (explicit user opt-in wins)', () => {
    const allow = buildScannerEnv({
      PATH: '/default/bin',
      SECURE_REVIEW_FORWARD_PATH: '/custom/bin',
    });
    expect(allow.PATH).toBe('/custom/bin');
  });

  it('ignores the bare prefix with no suffix', () => {
    const allow = buildScannerEnv({
      SECURE_REVIEW_FORWARD_: 'no-suffix-should-not-create-empty-key',
    });
    expect(allow['']).toBeUndefined();
    expect(allow.SECURE_REVIEW_FORWARD_).toBeUndefined();
  });

  it('forwards proxy env in both case forms (corporate proxy support)', () => {
    const allow = buildScannerEnv({
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

  it('forwards NODE_EXTRA_CA_CERTS (additive CA bundle, not TLS bypass)', () => {
    const allow = buildScannerEnv({ NODE_EXTRA_CA_CERTS: '/etc/ssl/corp-ca.pem' });
    expect(allow.NODE_EXTRA_CA_CERTS).toBe('/etc/ssl/corp-ca.pem');
  });

  it('snapshot: forwards exactly the documented scanner-relevant keys', () => {
    const probe: NodeJS.ProcessEnv = {
      // Should pass
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
      HTTP_PROXY: 'a',
      HTTPS_PROXY: 'a',
      NO_PROXY: 'a',
      http_proxy: 'a',
      https_proxy: 'a',
      no_proxy: 'a',
      NODE_EXTRA_CA_CERTS: 'a',
      DOCKER_HOST: 'a',
      DOCKER_CONFIG: 'a',
      DOCKER_CERT_PATH: 'a',
      DOCKER_TLS_VERIFY: 'a',
      DOCKER_BUILDKIT: 'a',
      NUCLEI_TEMPLATES_DIR: 'a',
      SECURE_REVIEW_FORWARD_FOO: 'a',
      // Should be blocked
      ANTHROPIC_API_KEY: 'BOOM',
      NODE_OPTIONS: 'BOOM',
      SSH_AUTH_SOCK: 'BOOM',
      DISPLAY: 'BOOM',
      PLAYWRIGHT_BROWSERS_PATH: 'BOOM',
    };
    const allow = buildScannerEnv(probe);
    expect(Object.keys(allow).sort()).toMatchInlineSnapshot(`
      [
        "DOCKER_BUILDKIT",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "FOO",
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
        "NUCLEI_TEMPLATES_DIR",
        "PATH",
        "SHELL",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "http_proxy",
        "https_proxy",
        "no_proxy",
      ]
    `);
  });
});

describe('buildAllowlistedEnv re-export from browser-login.ts (regression)', () => {
  it('still strips secrets and forwards browser-automation keys (the existing browser-login profile)', () => {
    const allow = buildAllowlistedEnv({
      PATH: '/usr/bin',
      ANTHROPIC_API_KEY: 'sk-secret',
      PLAYWRIGHT_BROWSERS_PATH: '/opt/pw',
      DISPLAY: ':0',
      DOCKER_HOST: 'tcp://daemon:2375', // browser profile excludes scanner-specific keys
    });
    expect(allow.PATH).toBe('/usr/bin');
    expect(allow.ANTHROPIC_API_KEY).toBeUndefined();
    expect(allow.PLAYWRIGHT_BROWSERS_PATH).toBe('/opt/pw');
    expect(allow.DISPLAY).toBe(':0');
    expect(allow.DOCKER_HOST).toBeUndefined();
  });
});
