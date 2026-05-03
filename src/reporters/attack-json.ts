import type { EvidenceJson } from 'secure-review';
import type { AttackAiModeOutput } from '../modes/attack-ai.js';
import type { AttackModeOutput } from '../modes/attack.js';

export interface JsonReportOptions {
  taskId: string;
  run: number;
  sourceCondition?: string;
  modelVersion: string;
  sessionId?: string;
  reviewerNames: string[];
}

export function renderAttackEvidence(
  out: AttackModeOutput,
  opts: JsonReportOptions,
): EvidenceJson & {
  target_url: string;
  checks: AttackModeOutput['checks'];
  runtime_findings: AttackModeOutput['findings'];
  gate_blocked: boolean;
  gate_reasons: string[];
} {
  return {
    task_id: opts.taskId,
    tool: 'secure-review',
    condition: 'F-attack',
    run: opts.run,
    timestamp: new Date().toISOString(),
    model_version: opts.modelVersion,
    source_condition: opts.sourceCondition,
    total_findings_initial: out.findings.length,
    findings_by_severity_initial: out.breakdown,
    total_findings_after_fix: out.findings.length,
    findings_by_severity_after_fix: out.breakdown,
    new_findings_introduced: 0,
    findings_resolved: 0,
    resolution_rate_pct: 0,
    semgrep_after_fix: 0,
    eslint_after_fix: 0,
    lines_of_code_fixed: 0,
    review_report: `Runtime attack run against ${out.targetUrl}`,
    session_id: opts.sessionId,
    generation_time_seconds: out.totalDurationMs / 1000,
    total_cost_usd: 0,
    review_status: 'ok',
    failed_reviewers: [],
    findings: out.findings,
    reviewers: opts.reviewerNames,
    iterations: 0,
    notes: out.gateBlocked ? `Gate blocked: ${out.gateReasons.join('; ')}` : undefined,
    target_url: out.targetUrl,
    checks: out.checks,
    runtime_findings: out.findings,
    gate_blocked: out.gateBlocked,
    gate_reasons: out.gateReasons,
  };
}

export function renderAttackAiEvidence(
  out: AttackAiModeOutput,
  opts: JsonReportOptions,
): EvidenceJson & {
  target_url: string;
  crawled_pages: AttackAiModeOutput['pages'];
  hypotheses: AttackAiModeOutput['hypotheses'];
  probes: AttackAiModeOutput['probes'];
  runtime_findings: AttackAiModeOutput['findings'];
  gate_blocked: boolean;
  gate_reasons: string[];
  limits: AttackAiModeOutput['limits'];
} {
  return {
    task_id: opts.taskId,
    tool: 'secure-review',
    condition: 'F-attack-ai',
    run: opts.run,
    timestamp: new Date().toISOString(),
    model_version: opts.modelVersion,
    source_condition: opts.sourceCondition,
    total_findings_initial: out.findings.length,
    findings_by_severity_initial: out.breakdown,
    total_findings_after_fix: out.findings.length,
    findings_by_severity_after_fix: out.breakdown,
    new_findings_introduced: 0,
    findings_resolved: 0,
    resolution_rate_pct: 0,
    semgrep_after_fix: 0,
    eslint_after_fix: 0,
    lines_of_code_fixed: 0,
    review_report: `AI attack simulation against ${out.targetUrl}`,
    session_id: opts.sessionId,
    generation_time_seconds: out.totalDurationMs / 1000,
    total_cost_usd: out.totalCostUSD,
    review_status: 'ok',
    failed_reviewers: [],
    findings: out.findings,
    reviewers: opts.reviewerNames,
    iterations: 0,
    notes: out.gateBlocked ? `Gate blocked: ${out.gateReasons.join('; ')}` : undefined,
    target_url: out.targetUrl,
    crawled_pages: out.pages,
    hypotheses: out.hypotheses,
    probes: out.probes,
    runtime_findings: out.findings,
    gate_blocked: out.gateBlocked,
    gate_reasons: out.gateReasons,
    limits: out.limits,
  };
}
