import { describe, it, expect } from 'vitest';
import { buildGhActionArgv } from '../src/cli.js';

const baseArgv = ['/usr/bin/node', '/path/to/cli.js'];

describe('buildGhActionArgv', () => {
  it('returns argv unchanged when not running under GitHub Actions', () => {
    const out = buildGhActionArgv(baseArgv, {});
    expect(out).toEqual(baseArgv);
  });

  it('returns argv unchanged when a subcommand is already present', () => {
    const argv = [...baseArgv, 'attack', '--target-url', 'http://x'];
    const out = buildGhActionArgv(argv, { GITHUB_ACTIONS: 'true', INPUT_MODE: 'attack-ai' });
    expect(out).toEqual(argv);
  });

  it('appends pr-runtime when in Actions runner with no subcommand', () => {
    const out = buildGhActionArgv(baseArgv, { GITHUB_ACTIONS: 'true' });
    expect(out).toEqual([...baseArgv, 'pr-runtime']);
  });

  it('translates INPUT_TARGET_URL to --target-url', () => {
    const out = buildGhActionArgv(baseArgv, {
      GITHUB_ACTIONS: 'true',
      INPUT_TARGET_URL: 'http://staging.example.com',
    });
    expect(out).toContain('--target-url');
    const idx = out.indexOf('--target-url');
    expect(out[idx + 1]).toBe('http://staging.example.com');
  });

  it('translates INPUT_RUNTIME_MODE to --runtime-mode', () => {
    const out = buildGhActionArgv(baseArgv, {
      GITHUB_ACTIONS: 'true',
      INPUT_RUNTIME_MODE: 'attack-ai',
    });
    const idx = out.indexOf('--runtime-mode');
    expect(out[idx + 1]).toBe('attack-ai');
  });

  it('translates INPUT_CONFIG and INPUT_MAX_COST_USD and INPUT_RUNTIME_TIMEOUT_SECONDS', () => {
    const out = buildGhActionArgv(baseArgv, {
      GITHUB_ACTIONS: 'true',
      INPUT_CONFIG: 'custom-config.yml',
      INPUT_MAX_COST_USD: '5',
      INPUT_RUNTIME_TIMEOUT_SECONDS: '600',
    });
    expect(out[out.indexOf('--config') + 1]).toBe('custom-config.yml');
    expect(out[out.indexOf('--max-cost-usd') + 1]).toBe('5');
    expect(out[out.indexOf('--runtime-timeout-seconds') + 1]).toBe('600');
  });

  it('appends --enable-runtime-attacks when INPUT_ENABLE_RUNTIME_ATTACKS=true', () => {
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
        INPUT_ENABLE_RUNTIME_ATTACKS: 'true',
      }),
    ).toContain('--enable-runtime-attacks');
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
        INPUT_ENABLE_RUNTIME_ATTACKS: '1',
      }),
    ).toContain('--enable-runtime-attacks');
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
        INPUT_ENABLE_RUNTIME_ATTACKS: 'yes',
      }),
    ).toContain('--enable-runtime-attacks');
  });

  it('does NOT append --enable-runtime-attacks for falsy / unset values', () => {
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
        INPUT_ENABLE_RUNTIME_ATTACKS: 'false',
      }),
    ).not.toContain('--enable-runtime-attacks');
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
        INPUT_ENABLE_RUNTIME_ATTACKS: '',
      }),
    ).not.toContain('--enable-runtime-attacks');
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
      }),
    ).not.toContain('--enable-runtime-attacks');
  });

  it('appends --autofix when INPUT_MODE=fix (deprecated path, but still wired)', () => {
    expect(
      buildGhActionArgv(baseArgv, {
        GITHUB_ACTIONS: 'true',
        INPUT_MODE: 'fix',
      }),
    ).toContain('--autofix');
  });

  it('does NOT append --autofix when INPUT_MODE is anything else', () => {
    for (const mode of ['attack', 'attack-ai', 'review', '']) {
      expect(
        buildGhActionArgv(baseArgv, {
          GITHUB_ACTIONS: 'true',
          INPUT_MODE: mode,
        }),
      ).not.toContain('--autofix');
    }
  });

  it('snapshot: a typical Action invocation produces exactly the expected argv', () => {
    const out = buildGhActionArgv(baseArgv, {
      GITHUB_ACTIONS: 'true',
      INPUT_MODE: 'attack',
      INPUT_RUNTIME_MODE: 'attack',
      INPUT_TARGET_URL: 'http://staging.example.com',
      INPUT_RUNTIME_TIMEOUT_SECONDS: '900',
      INPUT_MAX_COST_USD: '20',
      INPUT_ENABLE_RUNTIME_ATTACKS: 'true',
    });
    expect(out).toMatchInlineSnapshot(`
      [
        "/usr/bin/node",
        "/path/to/cli.js",
        "pr-runtime",
        "--max-cost-usd",
        "20",
        "--runtime-mode",
        "attack",
        "--target-url",
        "http://staging.example.com",
        "--runtime-timeout-seconds",
        "900",
        "--enable-runtime-attacks",
      ]
    `);
  });
});
