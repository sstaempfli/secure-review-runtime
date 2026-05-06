import { describe, it, expect } from 'vitest';
import {
  escapeBodyText,
  escapeFencedBlock,
  escapeHeading,
  escapeInlineCode,
  escapeTableCell,
} from '../src/internal/markdown-escape.js';
import { renderAttackReport, renderAttackAiReport } from '../src/reporters/attack-markdown.js';
import type { AttackModeOutput } from '../src/modes/attack.js';
import type { AttackAiModeOutput } from '../src/modes/attack-ai.js';

describe('escape helpers', () => {
  it('escapeInlineCode escapes internal backticks and collapses newlines', () => {
    expect(escapeInlineCode('safe-string')).toBe('safe-string');
    expect(escapeInlineCode('has`backtick')).toBe('has\\`backtick');
    expect(escapeInlineCode('multi\nline')).toBe('multi line');
    expect(escapeInlineCode('multi\r\nline')).toBe('multi line');
    expect(escapeInlineCode(undefined)).toBe('');
    expect(escapeInlineCode(null)).toBe('');
  });

  it('escapeTableCell escapes pipes, collapses newlines, bounds length', () => {
    expect(escapeTableCell('a|b')).toBe('a\\|b');
    expect(escapeTableCell('multi\nline')).toBe('multi line');
    expect(escapeTableCell('a'.repeat(300)).length).toBe(240);
    expect(escapeTableCell(404)).toBe('404');
    expect(escapeTableCell(undefined)).toBe('');
  });

  it('escapeFencedBlock neutralises triple backticks and HTML close tags', () => {
    expect(escapeFencedBlock('hi ```evil```')).toBe('hi \\`\\`\\`evil\\`\\`\\`');
    expect(escapeFencedBlock('</details>')).toBe('<\\/details>');
    expect(escapeFencedBlock('</summary>')).toBe('<\\/summary>');
    expect(escapeFencedBlock('</script>foo')).toBe('<\\/script>foo');
    expect(escapeFencedBlock('safe text')).toBe('safe text');
  });

  it('escapeBodyText neutralises triple backticks and HTML close tags', () => {
    expect(escapeBodyText('hi ```evil')).toBe('hi \\`\\`\\`evil');
    expect(escapeBodyText('</details>')).toBe('<\\/details>');
    expect(escapeBodyText('plain paragraph')).toBe('plain paragraph');
  });

  it('escapeHeading strips newlines + bounds length', () => {
    expect(escapeHeading('safe')).toBe('safe');
    expect(escapeHeading('with\nnewline')).toBe('with newline');
    expect(escapeHeading('a'.repeat(300)).length).toBe(240);
  });
});

describe('renderAttackReport with hostile finding fields', () => {
  function buildHostile(): AttackModeOutput {
    return {
      targetUrl: 'http://localhost:3000',
      checks: [
        {
          check: 'headers',
          url: 'http://localhost:3000/?q=`evil`',
          status: 200,
          ok: true,
          durationMs: 12,
          error: 'pipe|in|error\nnewline\ntoo',
        },
      ],
      findings: [
        {
          id: 'D-001',
          severity: 'HIGH',
          file: 'http://localhost:3000/`with-backticks`',
          lineStart: 0,
          lineEnd: 0,
          title: 'Title with | pipes and ```fences``` and </details>',
          description: '```js\nthrow new Error(\'</details>injection\');\n```\nsecond paragraph',
          remediation: 'Mitigation: avoid `eval` and `<script>` tags',
          reportedBy: ['dynamic'],
          confidence: 1,
          stableId: 'stable-with`backtick',
        },
      ],
      breakdown: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      gateBlocked: true,
      gateReasons: ['1 confirmed HIGH | reason with pipe'],
      totalDurationMs: 1234,
    } as AttackModeOutput;
  }

  it('produces a Markdown report with no unescaped table-breakers, no fence escapes, no </details> closes', () => {
    const md = renderAttackReport(buildHostile());

    // Sanity: report exists, has expected structure.
    expect(md).toContain('# Secure Review — Runtime Attack Report');
    expect(md).toContain('### D-001');

    // Table integrity: pipes inside cells must be escaped.
    expect(md).toMatch(/pipe\\\|in\\\|error/);
    // Newlines collapsed in table cells (no raw newline inside the row).
    expect(md.split('\n').some((line) => line.startsWith('| headers') && line.includes('newline too'))).toBe(true);

    // Backticks in inline-code positions are escaped.
    expect(md).toMatch(/with-backticks/);
    expect(md).toContain('\\`'); // some backtick was escaped somewhere

    // No raw triple-backtick from finding fields breaks fences:
    // body text contains the escaped form, not the raw form
    expect(md).not.toContain('```js');
    expect(md).toContain('\\`\\`\\`'); // escaped fence appears

    // No raw </details> from finding fields would close a parent <details>.
    expect(md).not.toMatch(/<\/details>/);
    expect(md).toContain('<\\/details>');

    // Gate reason pipe is escaped/preserved without breaking layout.
    expect(md).toContain('with pipe');
  });
});

describe('renderAttackAiReport with hostile probe fields', () => {
  function buildHostile(): AttackAiModeOutput {
    return {
      targetUrl: 'http://localhost:3000',
      pages: [],
      hypotheses: [],
      probes: [
        {
          hypothesisId: 'H-1',
          category: 'reflected_input',
          method: 'GET',
          url: 'http://localhost:3000/?q=`evil`|payload',
          status: 200,
          confirmed: false,
          error: 'multi\nline\nerror|with|pipes',
          durationMs: 12,
          evidence: {},
        },
      ],
      findings: [],
      breakdown: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      gateBlocked: false,
      gateReasons: [],
      usage: { inputTokens: 0, outputTokens: 0, costUSD: 0 },
      totalCostUSD: 0,
      totalDurationMs: 100,
      limits: { maxRequests: 50, maxCrawlPages: 20, rateLimitPerSecond: 2 },
      attacker: {
        provider: 'anthropic',
        model: 'has`backtick',
        skillPath: 'path/with`backticks/and|pipes',
      },
    } as AttackAiModeOutput;
  }

  it('escapes attacker model + skill path in inline-code positions', () => {
    const md = renderAttackAiReport(buildHostile());
    expect(md).toContain('# Secure Review — AI Attack Simulation Report');
    expect(md).toContain('\\`'); // backtick escaped in attacker line
    // Probe table row: pipe in url must be escaped within inline-code, error pipes escaped in cell
    expect(md).toMatch(/error\\\|with\\\|pipes/);
  });
});
