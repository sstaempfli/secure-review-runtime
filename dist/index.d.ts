import { DynamicCheck, SecureReviewConfig, Finding, SeverityBreakdown, Env, ModelAdapter, Provider, Usage, ModelRef, EvidenceJson } from 'secure-review';

interface AttackModeInput {
    root: string;
    config: SecureReviewConfig;
    targetUrl?: string;
    checks?: DynamicCheck[];
    timeoutSeconds?: number;
    /** Merged over `dynamic.auth_headers` (CLI / API overrides config). */
    authHeaders?: Record<string, string>;
}
interface AttackCheckResult {
    check: DynamicCheck | 'healthcheck';
    url: string;
    method: string;
    status?: number;
    ok: boolean;
    durationMs: number;
    evidence: Record<string, unknown>;
    error?: string;
}
interface AttackModeOutput {
    targetUrl: string;
    checks: AttackCheckResult[];
    findings: Finding[];
    breakdown: SeverityBreakdown;
    gateBlocked: boolean;
    gateReasons: string[];
    totalDurationMs: number;
}
declare function runAttackMode(input: AttackModeInput): Promise<AttackModeOutput>;

interface AttackAiModeInput {
    root: string;
    config: SecureReviewConfig;
    configDir: string;
    env: Env;
    targetUrl?: string;
    timeoutSeconds?: number;
    maxRequests?: number;
    maxCrawlPages?: number;
    rateLimitPerSecond?: number;
    attackerAdapter?: ModelAdapter;
    /** Preloaded skill body (test seam); if unset, skill is loaded from merged ref's skill path. */
    attackerSkill?: string;
    /**
     * Override attacker model vs `dynamic.attacker` / `writer` (CLI or API).
     * Unspecified fields still come from config (so you can set only `--attack-model`
     * and keep the provider from YAML).
     */
    attackerProvider?: Provider;
    attackerModel?: string;
    /** Skill path relative to config dir or absolute; overrides merged ref.skill when set. */
    attackerSkillPath?: string;
    /** Merged over `dynamic.auth_headers` for crawl, healthcheck, and probes. */
    authHeaders?: Record<string, string>;
    /**
     * Use Playwright (real Chromium) instead of the fetch-based crawler.
     * Requires `playwright` to be installed as a dev/peer dependency.
     * Enables JS rendering, SPA route discovery, and XHR/fetch interception.
     * Auth cookies from `--browser-login-script` are injected into the browser
     * context so the crawler operates as an authenticated user past login pages.
     */
    usePlaywright?: boolean;
}
interface AttackAiPage {
    url: string;
    status: number;
    title?: string;
    links: string[];
    forms: AttackAiForm[];
    /**
     * XHR/fetch paths observed during rendering (Playwright mode only).
     * These are API endpoints the page calls at runtime — invisible to the
     * fetch-based crawler and high-value targets for idor and auth_bypass probes.
     */
    apiEndpoints?: string[];
}
interface AttackAiForm {
    action: string;
    method: 'GET' | 'POST';
    fields: string[];
}
type AttackAiProbeCategory = 'reflected_input' | 'error_disclosure' | 'open_redirect' | 'path_exposure' | 'idor' | 'auth_bypass';
interface AttackAiHypothesis {
    id: string;
    category: AttackAiProbeCategory;
    severity: Finding['severity'];
    title: string;
    rationale: string;
    path: string;
    method: 'GET' | 'POST';
    parameter?: string;
    sourceFile?: string;
    lineStart?: number;
    remediation?: string;
}
interface AttackAiProbeResult {
    hypothesisId: string;
    category: AttackAiProbeCategory;
    url: string;
    method: 'GET' | 'POST';
    status?: number;
    confirmed: boolean;
    durationMs: number;
    evidence: Record<string, unknown>;
    error?: string;
}
interface AttackAiModeOutput {
    targetUrl: string;
    pages: AttackAiPage[];
    hypotheses: AttackAiHypothesis[];
    probes: AttackAiProbeResult[];
    findings: Finding[];
    breakdown: SeverityBreakdown;
    gateBlocked: boolean;
    gateReasons: string[];
    usage: Usage;
    totalCostUSD: number;
    totalDurationMs: number;
    limits: {
        maxRequests: number;
        maxCrawlPages: number;
        rateLimitPerSecond: number;
    };
    /** Effective attacker identity after merging config + CLI/API overrides. */
    attacker: {
        provider: string;
        model: string;
        skillPath: string;
    };
}
declare function runAttackAiMode(input: AttackAiModeInput): Promise<AttackAiModeOutput>;
/** Merge `dynamic.attacker` (or writer) with optional CLI/API overrides. */
declare function mergeAttackerRef(input: AttackAiModeInput): ModelRef;

declare function renderAttackReport(output: AttackModeOutput): string;
declare function renderAttackAiReport(output: AttackAiModeOutput): string;

interface JsonReportOptions {
    taskId: string;
    run: number;
    sourceCondition?: string;
    modelVersion: string;
    sessionId?: string;
    reviewerNames: string[];
}
declare function renderAttackEvidence(out: AttackModeOutput, opts: JsonReportOptions): EvidenceJson & {
    target_url: string;
    checks: AttackModeOutput['checks'];
    runtime_findings: AttackModeOutput['findings'];
    gate_blocked: boolean;
    gate_reasons: string[];
};
declare function renderAttackAiEvidence(out: AttackAiModeOutput, opts: JsonReportOptions): EvidenceJson & {
    target_url: string;
    crawled_pages: AttackAiModeOutput['pages'];
    hypotheses: AttackAiModeOutput['hypotheses'];
    probes: AttackAiModeOutput['probes'];
    runtime_findings: AttackAiModeOutput['findings'];
    gate_blocked: boolean;
    gate_reasons: string[];
    limits: AttackAiModeOutput['limits'];
};

declare function parsePentestScannerList(raw: string | undefined): Array<'zap-baseline' | 'nuclei'>;

/** Run ZAP baseline / Nuclei against `targetUrl` after built-in runtime probes (local CLI or CI). */
declare function runCliPentestScanners(kinds: Array<'zap-baseline' | 'nuclei'>, targetUrl: string, timeoutWallMs: number): Promise<{
    appendixMarkdown: string;
    findings: Finding[];
}>;

/** Read a GitHub Actions workflow `inputs` entry from `INPUT_<NAME>` env (hyphens → underscores, uppercased). */
declare function ghActionInput(name: string): string | undefined;

interface BrowserLoginHookResult {
    headers: Record<string, string>;
    stderr: string;
    durationMs: number;
}
/** Run a repo-local script (`node`) that prints one line of JSON `{ "headers": { "Cookie": "..." } }`. */
declare function runBrowserLoginScript(scriptPath: string, cwd: string, timeoutMs?: number): BrowserLoginHookResult;

interface PlaywrightCrawlInput {
    targetUrl: string;
    maxPages: number;
    timeoutMs: number;
    authHeaders?: Record<string, string>;
}
/**
 * Playwright-based crawler that replaces the fetch-based `crawlSameOrigin` when
 * `--playwright` is passed. Addresses the core limitation Ilya raised: the fetch
 * crawler cannot render JavaScript, discover SPA routes, or get past login pages.
 *
 * What this adds over the fetch crawler:
 * - Full Chromium rendering — React/Vue/Angular routes are navigable
 * - Auth cookies from `--browser-login-script` are injected into the browser
 *   context so the crawler operates as an authenticated user past login pages
 * - XHR/fetch interception: API endpoints the page calls at runtime are recorded
 *   as `apiEndpoints` on each page, giving the LLM planner extra attack surface
 *   (IDOR targets, auth-protected endpoints) that are invisible to curl/fetch
 *
 * Playwright is an optional peer. A clear install message is thrown if it is
 * absent rather than an opaque module-not-found crash.
 */
declare function crawlWithPlaywright(input: PlaywrightCrawlInput): Promise<AttackAiPage[]>;

export { type AttackAiForm, type AttackAiHypothesis, type AttackAiModeInput, type AttackAiModeOutput, type AttackAiPage, type AttackAiProbeResult, type AttackCheckResult, type AttackModeInput, type AttackModeOutput, type JsonReportOptions, type PlaywrightCrawlInput, crawlWithPlaywright, ghActionInput, mergeAttackerRef, parsePentestScannerList, renderAttackAiEvidence, renderAttackAiReport, renderAttackEvidence, renderAttackReport, runAttackAiMode, runAttackMode, runBrowserLoginScript, runCliPentestScanners };
