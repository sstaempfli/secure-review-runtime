import { describe, it, expect } from 'vitest';
import { mutateIdorPath } from '../src/modes/attack-ai.js';

describe('mutateIdorPath', () => {
  it('replaces a trailing numeric segment with the IDOR sentinel', () => {
    expect(mutateIdorPath('/api/users/42')).toBe('/api/users/9007199');
  });

  it('replaces the last numeric segment when multiple are present', () => {
    expect(mutateIdorPath('/api/orders/5/items/3')).toBe('/api/orders/5/items/9007199');
  });

  it('handles a single-segment numeric path', () => {
    expect(mutateIdorPath('/42')).toBe('/9007199');
  });

  it('preserves trailing slash', () => {
    expect(mutateIdorPath('/api/users/42/')).toBe('/api/users/9007199/');
  });

  it('returns path unchanged when no purely-numeric segment exists', () => {
    expect(mutateIdorPath('/api/users/profile')).toBe('/api/users/profile');
    expect(mutateIdorPath('/api/users/abc-123')).toBe('/api/users/abc-123');
    expect(mutateIdorPath('/api/health')).toBe('/api/health');
  });

  it('returns path unchanged if the only numeric segment is already the sentinel', () => {
    expect(mutateIdorPath('/api/users/9007199')).toBe('/api/users/9007199');
  });

  it('handles deep paths correctly', () => {
    expect(mutateIdorPath('/v2/org/7/project/15/secret')).toBe('/v2/org/7/project/9007199/secret');
  });
});
