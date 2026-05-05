import { describe, it, expect, vi, afterEach } from 'vitest';
import { log } from 'secure-review';
import { parseAuthHeadersJson } from '../src/cli.js';

const warnSpy = vi.spyOn(log, 'warn');

afterEach(() => {
  warnSpy.mockClear();
});

describe('parseAuthHeadersJson', () => {
  it('returns undefined for empty / whitespace input without warning', () => {
    expect(parseAuthHeadersJson(undefined)).toBeUndefined();
    expect(parseAuthHeadersJson('')).toBeUndefined();
    expect(parseAuthHeadersJson('   ')).toBeUndefined();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('parses a valid object of string→string', () => {
    const headers = parseAuthHeadersJson('{"X-Token": "abc", "Cookie": "session=xyz"}');
    expect(headers).toEqual({ 'X-Token': 'abc', Cookie: 'session=xyz' });
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('warns and returns undefined on malformed JSON (no longer silent)', () => {
    const headers = parseAuthHeadersJson('{"invalid');
    expect(headers).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/JSON parse failed/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/Probes will run unauthenticated/);
  });

  it('warns and returns undefined when JSON is an array (must be a plain object)', () => {
    const headers = parseAuthHeadersJson('["X-Token", "abc"]');
    expect(headers).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/expected a JSON object/);
  });

  it('warns and returns undefined when JSON is null', () => {
    const headers = parseAuthHeadersJson('null');
    expect(headers).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  it('warns and returns undefined when JSON is a primitive (string, number)', () => {
    expect(parseAuthHeadersJson('"just-a-string"')).toBeUndefined();
    expect(parseAuthHeadersJson('42')).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledTimes(2);
  });

  it('warns when a header value is not a string but keeps the string-valued ones', () => {
    const headers = parseAuthHeadersJson('{"X-Token": "abc", "X-Count": 42, "X-Bool": true}');
    expect(headers).toEqual({ 'X-Token': 'abc' });
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/2 header values dropped/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/X-Count/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/X-Bool/);
  });

  it('returns undefined when ALL values are non-string (warn only, no headers)', () => {
    const headers = parseAuthHeadersJson('{"X-Count": 42}');
    expect(headers).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });
});
