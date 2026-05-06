import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { log } from 'secure-review';
import { runBrowserLoginScript } from '../src/pentest/browser-login.js';

const tmpDirs: string[] = [];
const warnSpy = vi.spyOn(log, 'warn');

afterEach(() => {
  warnSpy.mockClear();
  while (tmpDirs.length) {
    const d = tmpDirs.pop()!;
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

function mkTmp(prefix = 'srrt-bl-'): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tmpDirs.push(d);
  return d;
}

describe('runBrowserLoginScript path validation', () => {
  it('rejects an empty / whitespace-only path with a clear message', () => {
    const cwd = mkTmp();
    expect(() => runBrowserLoginScript('   ', cwd)).toThrow(/path is empty/);
    expect(() => runBrowserLoginScript('', cwd)).toThrow(/path is empty/);
  });

  it('rejects a non-existent path with the absolute path in the message', () => {
    const cwd = mkTmp();
    expect(() => runBrowserLoginScript('does-not-exist.mjs', cwd)).toThrow(/not found/);
  });

  it('rejects a path that resolves to a directory', () => {
    const cwd = mkTmp();
    const subdir = join(cwd, 'sub');
    mkdirSync(subdir);
    expect(() => runBrowserLoginScript('sub', cwd)).toThrow(/is a directory, not a file/);
  });

  it('trims whitespace from the input path before resolving', () => {
    const cwd = mkTmp();
    const scriptPath = join(cwd, 'probe.mjs');
    writeFileSync(scriptPath, `console.log('{"headers":{"X-OK":"yes"}}');\n`);
    // Leading + trailing whitespace must be tolerated (common copy-paste).
    const result = runBrowserLoginScript('  probe.mjs  ', cwd);
    expect(result.headers['X-OK']).toBe('yes');
  });

  it('accepts a symlink that resolves to a regular file', () => {
    const cwd = mkTmp();
    const realScript = join(cwd, 'real.mjs');
    const symlinkPath = join(cwd, 'link.mjs');
    writeFileSync(realScript, `console.log('{"headers":{"X-OK":"via-symlink"}}');\n`);
    try {
      symlinkSync(realScript, symlinkPath);
    } catch {
      // Some filesystems / sandboxes don't allow symlinks; skip in that case.
      return;
    }
    const result = runBrowserLoginScript('link.mjs', cwd);
    expect(result.headers['X-OK']).toBe('via-symlink');
  });
});

describe('runBrowserLoginScript JSON payload validation', () => {
  function makeProbe(content: string): { scriptPath: string; cwd: string } {
    const cwd = mkTmp();
    const scriptPath = join(cwd, 'probe.mjs');
    writeFileSync(scriptPath, content);
    return { scriptPath, cwd };
  }

  it('rejects when the script prints an array (instead of an object)', () => {
    const { cwd } = makeProbe(`console.log('["X-Token", "abc"]');\n`);
    expect(() => runBrowserLoginScript('probe.mjs', cwd)).toThrow(/must be an object with a "headers" property/);
  });

  it('rejects when the script prints null', () => {
    const { cwd } = makeProbe(`console.log('null');\n`);
    expect(() => runBrowserLoginScript('probe.mjs', cwd)).toThrow(/must be an object with a "headers" property/);
  });

  it('rejects when "headers" is itself an array', () => {
    const { cwd } = makeProbe(`console.log('{"headers": ["a", "b"]}');\n`);
    expect(() => runBrowserLoginScript('probe.mjs', cwd)).toThrow(/"headers" must be a plain object/);
  });

  it('rejects when "headers" is missing', () => {
    const { cwd } = makeProbe(`console.log('{"foo": 1}');\n`);
    expect(() => runBrowserLoginScript('probe.mjs', cwd)).toThrow(/"headers" must be a plain object/);
  });

  it('rejects when "headers" is null', () => {
    const { cwd } = makeProbe(`console.log('{"headers": null}');\n`);
    expect(() => runBrowserLoginScript('probe.mjs', cwd)).toThrow(/"headers" must be a plain object/);
  });

  it('accepts a valid object payload and warns when non-string header values are dropped', () => {
    const { cwd } = makeProbe(
      `console.log('{"headers": {"X-Token": "abc", "X-Count": 42, "X-Bool": true}}');\n`,
    );
    const result = runBrowserLoginScript('probe.mjs', cwd);
    expect(result.headers).toEqual({ 'X-Token': 'abc' });
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/2 header values dropped/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/X-Count/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/X-Bool/);
  });

  it('does NOT warn when all header values are valid strings', () => {
    const { cwd } = makeProbe(`console.log('{"headers": {"X-Token": "abc"}}');\n`);
    const result = runBrowserLoginScript('probe.mjs', cwd);
    expect(result.headers).toEqual({ 'X-Token': 'abc' });
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
