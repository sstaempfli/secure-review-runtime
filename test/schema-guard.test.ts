import { describe, it, expect } from 'vitest';
import { assertRuntimeConfigShape } from '../src/internal/schema-guard.js';

describe('assertRuntimeConfigShape', () => {
  it('accepts a valid config (dynamic.enabled boolean, optional target_url, optional gates.max_cost_usd)', () => {
    expect(() =>
      assertRuntimeConfigShape({
        dynamic: { enabled: true, target_url: 'http://localhost:3000' },
        gates: { max_cost_usd: 1.5 },
      }),
    ).not.toThrow();
  });

  it('accepts a minimal config (only dynamic.enabled)', () => {
    expect(() => assertRuntimeConfigShape({ dynamic: { enabled: false } })).not.toThrow();
  });

  it('rejects non-object config', () => {
    expect(() => assertRuntimeConfigShape(null)).toThrow(/not an object/);
    expect(() => assertRuntimeConfigShape('string')).toThrow(/not an object/);
    expect(() => assertRuntimeConfigShape(42)).toThrow(/not an object/);
  });

  it('rejects missing dynamic block', () => {
    expect(() => assertRuntimeConfigShape({})).toThrow(/config\.dynamic is missing/);
  });

  it('rejects dynamic.enabled missing or wrong-typed', () => {
    expect(() => assertRuntimeConfigShape({ dynamic: {} })).toThrow(
      /config\.dynamic\.enabled is missing/,
    );
    expect(() =>
      assertRuntimeConfigShape({ dynamic: { enabled: 'true' as unknown as boolean } }),
    ).toThrow(/config\.dynamic\.enabled .* not a boolean/);
    expect(() =>
      assertRuntimeConfigShape({ dynamic: { enabled: 1 as unknown as boolean } }),
    ).toThrow(/config\.dynamic\.enabled .* not a boolean/);
  });

  it('rejects target_url with wrong type when present', () => {
    expect(() =>
      assertRuntimeConfigShape({ dynamic: { enabled: true, target_url: 42 } }),
    ).toThrow(/target_url is set but not a string/);
  });

  it('accepts target_url undefined (optional field)', () => {
    expect(() => assertRuntimeConfigShape({ dynamic: { enabled: true } })).not.toThrow();
  });

  it('rejects gates.max_cost_usd with wrong type when present', () => {
    expect(() =>
      assertRuntimeConfigShape({
        dynamic: { enabled: true },
        gates: { max_cost_usd: '20' as unknown as number },
      }),
    ).toThrow(/max_cost_usd is set but not a number/);
  });

  it('accepts gates undefined (optional)', () => {
    expect(() => assertRuntimeConfigShape({ dynamic: { enabled: true } })).not.toThrow();
  });

  it('error message names the bad keys and suggests pinning the peer', () => {
    try {
      assertRuntimeConfigShape({ dynamic: {} });
      throw new Error('should have thrown');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      expect(msg).toMatch(/secure-review schema mismatch/);
      expect(msg).toMatch(/dynamic\.enabled/);
      expect(msg).toMatch(/Pin `secure-review`/);
    }
  });
});
