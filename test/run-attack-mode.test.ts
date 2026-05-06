import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { runAttackMode } from '../src/modes/attack.js';
import type { SecureReviewConfig } from 'secure-review';

/**
 * In-process stub HTTP server with deliberate flaws so each of the four
 * deterministic attack-mode checks (`headers`, `cookies`, `cors`,
 * `sensitive_paths`) has something to find. Exercises the same code paths
 * the README quickstart demonstrates against `examples/vulnerable-target/`,
 * but lives entirely inside vitest so CI doesn't need a separate process.
 */

let server: Server;
let port: number;

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      server = createServer((req, res) => {
        // CORS: reflect Origin + credentials (textbook misconfiguration)
        if (req.headers.origin) {
          res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
          res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        // Information disclosure
        res.setHeader('Server', 'stub-vulnerable/0.1.0');
        // Cookie without HttpOnly / Secure / SameSite
        res.setHeader('Set-Cookie', 'session=demo-session-id; Path=/');

        if (req.url === '/.env') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('SECRET_KEY=demo-not-real\n');
          return;
        }
        // Otherwise: 200 OK with no CSP / HSTS / X-Frame-Options / X-Content-Type-Options
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><body>vulnerable stub</body></html>');
      });
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') port = addr.port;
        resolve();
      });
    }),
);

afterAll(() => {
  return new Promise<void>((resolve) => server.close(() => resolve()));
});

function buildConfig(targetUrl: string): SecureReviewConfig {
  // Minimal SecureReviewConfig for runtime-attack tests. Writer/reviewers
  // are placeholders — the deterministic `attack` mode never invokes them.
  return {
    writer: {
      provider: 'anthropic',
      model: 'claude-sonnet-4-6',
      skill: './placeholder.md',
    },
    reviewers: [
      {
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        skill: './placeholder.md',
        name: 'placeholder',
      },
    ],
    review: {
      max_iterations: 3,
      include_globs: ['**/*'],
      exclude_globs: [],
      max_files: 100,
      max_bytes_per_file: 200_000,
    },
    fix: {
      ignore_findings: [],
    },
    gates: {
      block_on_new_critical: true,
      block_on_new_high: false,
      max_cost_usd: 0,
      max_wall_time_minutes: 0,
    },
    sast: {
      enabled: false,
      tools: ['semgrep', 'eslint', 'npm_audit'],
      inject_into_reviewer_context: false,
    },
    dynamic: {
      enabled: true,
      target_url: targetUrl,
      timeout_seconds: 5,
      max_requests: 50,
      rate_limit_per_second: 10,
      max_crawl_pages: 5,
      checks: ['headers', 'cookies', 'cors', 'sensitive_paths'],
      sensitive_paths: ['/.env'],
      gates: {
        block_on_confirmed_critical: true,
        block_on_confirmed_high: false,
      },
    },
    output: {
      report: './reports/report-{timestamp}.md',
      findings: './reports/findings-{timestamp}.json',
      diff: './reports/diff-{timestamp}.patch',
    },
  } as unknown as SecureReviewConfig;
}

describe('runAttackMode against an in-process vulnerable stub', () => {
  it('produces findings across all four deterministic check categories', async () => {
    const targetUrl = `http://127.0.0.1:${port}`;
    const config = buildConfig(targetUrl);
    const out = await runAttackMode({ root: process.cwd(), config });

    // Sanity: hit the right target
    expect(out.targetUrl).toBe(`http://127.0.0.1:${port}/`);

    // Each check category should produce at least one finding against the stub.
    // Findings include the originating check name in their reportedBy list,
    // so we can group by category here.
    const checksRun = new Set(out.checks.map((c) => c.check));
    expect(checksRun.has('headers')).toBe(true);
    expect(checksRun.has('cookies')).toBe(true);
    expect(checksRun.has('cors')).toBe(true);
    expect(checksRun.has('sensitive_paths')).toBe(true);

    // We expect at least 5 findings total (CSP missing, HSTS missing,
    // X-Frame-Options missing, weak Set-Cookie attributes, /.env exposed).
    expect(out.findings.length).toBeGreaterThanOrEqual(5);

    // The /.env exposure should be one of the findings.
    const sensitiveHits = out.findings.filter((f) =>
      String(f.file).includes('/.env') || /env/i.test(f.title),
    );
    expect(sensitiveHits.length).toBeGreaterThanOrEqual(1);

    // Header gaps must surface as findings.
    const headerHits = out.findings.filter((f) =>
      /CSP|HSTS|X-Frame|content-security|strict-transport|frame-options/i.test(`${f.title} ${f.description}`),
    );
    expect(headerHits.length).toBeGreaterThanOrEqual(2);

    // The deterministic mode runs in well under a second per probe.
    expect(out.totalDurationMs).toBeLessThan(10_000);

    // Severity breakdown is consistent with finding count.
    const totalFromBreakdown =
      out.breakdown.CRITICAL + out.breakdown.HIGH + out.breakdown.MEDIUM + out.breakdown.LOW + out.breakdown.INFO;
    expect(totalFromBreakdown).toBe(out.findings.length);
  });

  it('respects --target-url override over config.dynamic.target_url', async () => {
    const config = buildConfig('http://example.invalid:9999');
    const out = await runAttackMode({
      root: process.cwd(),
      config,
      targetUrl: `http://127.0.0.1:${port}`,
    });
    expect(out.targetUrl).toBe(`http://127.0.0.1:${port}/`);
    expect(out.findings.length).toBeGreaterThan(0);
  });
});
