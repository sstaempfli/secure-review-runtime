import { describe, it, expect } from 'vitest';
import { RequestBudget } from '../src/modes/attack-ai.js';

describe('RequestBudget — clamps invalid config defensively', () => {
  it('clamps rateLimitPerSecond=0 (would divide by zero) to 0.1', async () => {
    const b = new RequestBudget(50, 0);
    // remaining() and tryTake() should both work; minIntervalMs becomes
    // Math.ceil(1000 / 0.1) = 10_000, but the FIRST take has lastRequestAt=0
    // so it goes through immediately.
    expect(b.remaining()).toBe(50);
    expect(await b.tryTake()).toBe(true);
    expect(b.remaining()).toBe(49);
    // Don't try a second take in this test — the 10-second wait would
    // make the suite slow. The point is just that no Infinity / NaN /
    // throw escaped from construction or first take.
  });

  it('clamps a negative rateLimitPerSecond to 0.1 (no silent disable)', async () => {
    const b = new RequestBudget(50, -5);
    expect(await b.tryTake()).toBe(true);
  });

  it('clamps NaN rateLimitPerSecond to 0.1', async () => {
    const b = new RequestBudget(50, Number.NaN);
    expect(await b.tryTake()).toBe(true);
  });

  it('clamps maxRequests=0 to 1 so planner is not locked out', async () => {
    const b = new RequestBudget(0, 2);
    expect(b.remaining()).toBe(1);
    expect(await b.tryTake()).toBe(true);
    expect(b.remaining()).toBe(0);
    expect(await b.tryTake()).toBe(false);
  });

  it('clamps a negative maxRequests to 1', async () => {
    const b = new RequestBudget(-10, 2);
    expect(b.remaining()).toBe(1);
  });

  it('floors a fractional maxRequests', async () => {
    const b = new RequestBudget(3.7, 2);
    expect(b.remaining()).toBe(3);
  });

  it('honours a sane configuration (50 max, 2/second) and counts down on take', async () => {
    const b = new RequestBudget(50, 2);
    expect(b.remaining()).toBe(50);
    expect(await b.tryTake()).toBe(true);
    expect(b.remaining()).toBe(49);
  });

  it('returns false from tryTake() once maxRequests is exhausted', async () => {
    const b = new RequestBudget(2, 50);
    expect(await b.tryTake()).toBe(true);
    expect(await b.tryTake()).toBe(true);
    expect(await b.tryTake()).toBe(false);
    expect(b.remaining()).toBe(0);
  });
});
