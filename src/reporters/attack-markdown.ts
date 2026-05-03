import type { Finding, SeverityBreakdown } from 'secure-review';
import { SEVERITY_ORDER } from 'secure-review';
import { agreementCount } from 'secure-review';
import type { AttackAiModeOutput } from '../modes/attack-ai.js';
import type { AttackModeOutput } from '../modes/attack.js';

export function renderAttackReport(output: AttackModeOutput): string {
  const parts: string[] = [];
  parts.push(`# Secure Review — Runtime Attack Report`);
  parts.push(`\nGenerated: ${new Date().toISOString()}`);
  parts.push(`Target: ${output.targetUrl}`);
  parts.push(`Duration: ${(output.totalDurationMs / 1000).toFixed(1)}s`);
  parts.push(`Gate blocked: ${output.gateBlocked ? 'YES' : 'no'}`);
  if (output.gateReasons.length) parts.push(`Reasons: ${output.gateReasons.join('; ')}`);
  parts.push('');

  parts.push(`## Summary\n`);
  parts.push(breakdownTable(output.breakdown));
  parts.push('');
  parts.push(`Total runtime findings: **${output.findings.length}**\n`);

  parts.push(`## Checks\n`);
  parts.push('| Check | URL | Status | OK | Duration | Error |');
  parts.push('|---|---|---:|---|---:|---|');
  for (const c of output.checks) {
    parts.push(
      `| ${c.check} | \`${c.url}\` | ${c.status ?? ''} | ${c.ok ? 'yes' : 'no'} | ${(c.durationMs / 1000).toFixed(1)}s | ${c.error ?? ''} |`,
    );
  }
  parts.push('');

  parts.push(`## Runtime Findings\n`);
  if (output.findings.length === 0) {
    parts.push('_No runtime findings._');
  } else {
    const sorted = sortByAgreement(output.findings);
    for (const f of sorted) parts.push(renderFinding(f));
  }

  return parts.join('\n');
}

export function renderAttackAiReport(output: AttackAiModeOutput): string {
  const parts: string[] = [];
  parts.push(`# Secure Review — AI Attack Simulation Report`);
  parts.push(`\nGenerated: ${new Date().toISOString()}`);
  parts.push(`Target: ${output.targetUrl}`);
  parts.push(
    `Attacker: **${output.attacker.provider}** / \`${output.attacker.model}\` · skill: \`${output.attacker.skillPath}\``,
  );
  parts.push(`Duration: ${(output.totalDurationMs / 1000).toFixed(1)}s`);
  parts.push(`Cost: $${output.totalCostUSD.toFixed(3)}`);
  parts.push(`Gate blocked: ${output.gateBlocked ? 'YES' : 'no'}`);
  if (output.gateReasons.length) parts.push(`Reasons: ${output.gateReasons.join('; ')}`);
  parts.push('');

  parts.push(`## Summary\n`);
  parts.push(breakdownTable(output.breakdown));
  parts.push('');
  parts.push(`Crawled pages: **${output.pages.length}**`);
  parts.push(`Hypotheses planned: **${output.hypotheses.length}**`);
  parts.push(`Safe probes executed: **${output.probes.length}**`);
  parts.push(`Confirmed findings: **${output.findings.length}**\n`);

  parts.push(`## Safety Limits\n`);
  parts.push(`- Same-origin requests only`);
  parts.push(`- Max requests: ${output.limits.maxRequests}`);
  parts.push(`- Max crawl pages: ${output.limits.maxCrawlPages}`);
  parts.push(`- Rate limit: ${output.limits.rateLimitPerSecond}/second`);
  parts.push('');

  parts.push(`## Probes\n`);
  parts.push('| Hypothesis | Category | Method | URL | Status | Confirmed | Error |');
  parts.push('|---|---|---|---|---:|---|---|');
  for (const p of output.probes) {
    parts.push(
      `| ${p.hypothesisId} | ${p.category} | ${p.method} | \`${p.url}\` | ${p.status ?? ''} | ${p.confirmed ? 'yes' : 'no'} | ${p.error ?? ''} |`,
    );
  }
  parts.push('');

  parts.push(`## Confirmed Findings\n`);
  if (output.findings.length === 0) {
    parts.push('_No AI-planned probes produced confirmed runtime evidence._');
  } else {
    const sorted = sortByAgreement(output.findings);
    for (const f of sorted) parts.push(renderFinding(f));
  }

  return parts.join('\n');
}

function renderFinding(f: Finding): string {
  const reporters = f.reportedBy.join(', ');
  const tags = [f.cwe, f.owaspCategory].filter(Boolean).join(' · ');
  const count = agreementCount(f);
  const agreementBadge = count > 1 ? ` · ✅ confirmed by ${count} models` : '';
  const stableTag = f.stableId ? ` [${f.stableId}]` : '';
  return `
### ${f.id}${stableTag} · **${f.severity}** · ${f.title}${agreementBadge}

- **File:** \`${f.file}:${f.lineStart}-${f.lineEnd}\`
- **Tags:** ${tags || '—'}
- **Reported by:** ${reporters}  (confidence: ${(f.confidence * 100).toFixed(0)}%, agreement: ${count} model${count !== 1 ? 's' : ''})

${f.description}

${f.remediation ? `**Remediation:** ${f.remediation}` : ''}
`;
}

function sortByAgreement(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const cntDiff = agreementCount(b) - agreementCount(a);
    if (cntDiff !== 0) return cntDiff;
    return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
  });
}

function breakdownTable(b: SeverityBreakdown): string {
  const rows = ['| CRITICAL | HIGH | MEDIUM | LOW | INFO |', '|---:|---:|---:|---:|---:|'];
  rows.push(`| ${b.CRITICAL} | ${b.HIGH} | ${b.MEDIUM} | ${b.LOW} | ${b.INFO} |`);
  return rows.join('\n');
}
