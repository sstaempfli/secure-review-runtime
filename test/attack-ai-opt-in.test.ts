import { describe, it, expect } from 'vitest';
import { isRuntimeAttackAllowed, parseBooleanFlag } from '../src/runtime-gate.js';

describe('isRuntimeAttackAllowed', () => {
  it('blocks by default when neither flag nor config opts in', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: { enabled: false } }, false);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      // The reason should name dynamic.enabled (or its YAML equivalent) and the CLI flag.
      expect(decision.reason).toMatch(/dynamic:/);
      expect(decision.reason).toMatch(/enabled: true/);
      expect(decision.reason).toMatch(/--enable-runtime-attacks/);
    }
  });

  it('blocks when dynamic.enabled is undefined and flag is false', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: {} }, false);
    expect(decision.allowed).toBe(false);
  });

  it('allows when dynamic.enabled is true (config opt-in)', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: { enabled: true } }, false);
    expect(decision.allowed).toBe(true);
  });

  it('allows when CLI flag is true even if dynamic.enabled is false', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: { enabled: false } }, true);
    expect(decision.allowed).toBe(true);
  });

  it('allows when CLI flag is true and dynamic config is missing', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: {} }, true);
    expect(decision.allowed).toBe(true);
  });

  it('treats undefined flag the same as false (no opt-in)', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: { enabled: false } }, undefined);
    expect(decision.allowed).toBe(false);
  });

  it('does NOT allow when dynamic.enabled is the string "true" (must be a real boolean)', () => {
    // Defends against config-loaders that surface YAML strings instead of bools.
    // The schema in `secure-review` parses to a real boolean; if for any reason
    // a stale parsed value sneaks in as a truthy non-boolean, the gate must NOT
    // open silently.
    const decision = isRuntimeAttackAllowed(
      { dynamic: { enabled: 'true' as unknown as boolean } },
      false,
    );
    expect(decision.allowed).toBe(false);
  });

  it('reason mentions all three opt-in routes (config YAML, CLI flag, Action input) so the user can fix it', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: { enabled: false } }, false);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      // Config YAML route
      expect(decision.reason).toMatch(/dynamic:/);
      expect(decision.reason).toMatch(/enabled: true/);
      // CLI flag route
      expect(decision.reason).toMatch(/--enable-runtime-attacks/);
      // GH Action input route
      expect(decision.reason).toMatch(/enable-runtime-attacks: true/);
    }
  });

  it('reason includes a literal copy-pasteable YAML snippet (so the user can fix it in 10 seconds)', () => {
    const decision = isRuntimeAttackAllowed({ dynamic: { enabled: false } }, false);
    if (!decision.allowed) {
      // The 3-line YAML snippet must be intact and indented for paste-ready use.
      expect(decision.reason).toContain('dynamic:');
      expect(decision.reason).toContain('  enabled: true');
    }
  });
});

describe('parseBooleanFlag (GH Action input parsing)', () => {
  it('returns true for "true"', () => {
    expect(parseBooleanFlag('true')).toBe(true);
    expect(parseBooleanFlag('TRUE')).toBe(true);
    expect(parseBooleanFlag('True')).toBe(true);
  });

  it('returns true for "1", "yes", "on"', () => {
    expect(parseBooleanFlag('1')).toBe(true);
    expect(parseBooleanFlag('yes')).toBe(true);
    expect(parseBooleanFlag('YES')).toBe(true);
    expect(parseBooleanFlag('on')).toBe(true);
  });

  it('returns false for "false", "0", "no", "off", empty, undefined', () => {
    expect(parseBooleanFlag('false')).toBe(false);
    expect(parseBooleanFlag('FALSE')).toBe(false);
    expect(parseBooleanFlag('0')).toBe(false);
    expect(parseBooleanFlag('no')).toBe(false);
    expect(parseBooleanFlag('off')).toBe(false);
    expect(parseBooleanFlag('')).toBe(false);
    expect(parseBooleanFlag('   ')).toBe(false);
    expect(parseBooleanFlag(undefined)).toBe(false);
  });

  it('returns false for unrelated truthy-looking strings (defensive default-deny)', () => {
    expect(parseBooleanFlag('enable')).toBe(false);
    expect(parseBooleanFlag('please')).toBe(false);
    expect(parseBooleanFlag('y')).toBe(false); // explicit: only "yes", not "y"
  });

  it('trims whitespace before comparing', () => {
    expect(parseBooleanFlag('  true  ')).toBe(true);
    expect(parseBooleanFlag('\ttrue\n')).toBe(true);
  });
});
