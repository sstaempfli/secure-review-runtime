#!/usr/bin/env node
import {
  ghActionInput,
  parsePentestScannerList,
  renderAttackAiEvidence,
  renderAttackAiReport,
  renderAttackEvidence,
  renderAttackReport,
  runAttackAiMode,
  runAttackMode,
  runBrowserLoginScript,
  runCliPentestScanners
} from "./chunk-YSJT4XDO.js";

// src/cli.ts
import { readFile } from "fs/promises";
import { existsSync, realpathSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { Command, InvalidArgumentError } from "commander";
import { z } from "zod";
import { loadConfig, loadEnv } from "secure-review";
import { severityBreakdown } from "secure-review";
import { evaluateRuntimePrGate, postPrMarkdownReview } from "secure-review";
import { writeFileSafe } from "secure-review";
import { log, setQuiet, setVerbose } from "secure-review";
import {
  DynamicCheck,
  Provider
} from "secure-review";
import { mergeAuthHeaders } from "secure-review";

// src/runtime-gate.ts
function isRuntimeAttackAllowed(config, enableFlag) {
  if (enableFlag === true) return { allowed: true };
  if (config.dynamic.enabled === true) return { allowed: true };
  return {
    allowed: false,
    reason: "Runtime attacks are not enabled. Set `dynamic.enabled: true` in your config (.secure-review.yml) or pass `--enable-runtime-attacks` (CLI) / `enable-runtime-attacks: true` (GitHub Action input) to opt in. Skipping runtime probes; no requests sent."
  };
}
function parseBooleanFlag(raw) {
  if (raw === void 0 || raw === null) return false;
  const v = raw.trim().toLowerCase();
  return v === "true" || v === "1" || v === "yes" || v === "on";
}

// src/cli.ts
if (existsSync(".env")) {
  try {
    process.loadEnvFile(".env");
  } catch {
  }
}
var DEFAULT_OUTPUT = {
  report: "./reports/report-{timestamp}.md",
  findings: "./reports/findings-{timestamp}.json",
  diff: "./reports/diff-{timestamp}.patch"
};
function timestamp() {
  return (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
}
function outputPath(configured, defaultConfigured, outputDir, fallbackName, stamp) {
  const path = configured === defaultConfigured ? resolve(outputDir, fallbackName) : configured;
  return resolve(path.replaceAll("{timestamp}", stamp));
}
function parseMaxIterations(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("max iterations must be an integer from 1 to 10");
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 10) {
    throw new InvalidArgumentError("max iterations must be an integer from 1 to 10");
  }
  return n;
}
function parseMaxCostUsd(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("max cost must be a finite number greater than or equal to 0");
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw new InvalidArgumentError("max cost must be a finite number greater than or equal to 0");
  }
  return n;
}
function parseMaxWallTimeMinutes(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("wall-time cap must be a finite number greater than 0 minutes");
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new InvalidArgumentError("wall-time cap must be a finite number greater than 0 minutes");
  }
  return n;
}
function parseTimeoutSeconds(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("timeout must be an integer from 1 to 600 seconds");
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 600) {
    throw new InvalidArgumentError("timeout must be an integer from 1 to 600 seconds");
  }
  return n;
}
function parseRuntimePrTimeoutSeconds(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 30 || n > 7200) {
    throw new InvalidArgumentError("runtime-timeout-seconds must be an integer from 30 to 7200");
  }
  return n;
}
function parseMaxRequests(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("max requests must be an integer from 1 to 500");
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 500) {
    throw new InvalidArgumentError("max requests must be an integer from 1 to 500");
  }
  return n;
}
function parseMaxCrawlPages(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("max crawl pages must be an integer from 1 to 100");
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 100) {
    throw new InvalidArgumentError("max crawl pages must be an integer from 1 to 100");
  }
  return n;
}
function parseRateLimit(raw) {
  if (raw.trim() === "") throw new InvalidArgumentError("rate limit must be a number greater than 0 and at most 20");
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || n > 20) {
    throw new InvalidArgumentError("rate limit must be a number greater than 0 and at most 20");
  }
  return n;
}
function parseAttackProvider(raw) {
  const parsed = Provider.safeParse(raw.trim().toLowerCase());
  if (!parsed.success) {
    throw new InvalidArgumentError("attack provider must be anthropic, openai, or google");
  }
  return parsed.data;
}
function parseAuthHeaderLine(raw) {
  const trimmed = raw.trim();
  const idx = trimmed.indexOf(":");
  if (idx <= 0) {
    throw new InvalidArgumentError(
      `Invalid header "${raw}": expected "Name: value" (first colon separates name from value)`
    );
  }
  const name = trimmed.slice(0, idx).trim();
  const value = trimmed.slice(idx + 1).trim();
  if (!name) throw new InvalidArgumentError(`Invalid header "${raw}": empty header name`);
  return { name, value };
}
function authHeadersFromCliList(lines) {
  if (!lines?.length) return void 0;
  const out = {};
  for (const line of lines) {
    const { name, value } = parseAuthHeaderLine(line);
    out[name] = value;
  }
  return out;
}
function parseAuthHeadersJson(raw) {
  if (!raw?.trim()) return void 0;
  try {
    const o = JSON.parse(raw);
    const out = {};
    for (const [k, v] of Object.entries(o)) {
      if (typeof v === "string") out[k] = v;
    }
    return Object.keys(out).length > 0 ? out : void 0;
  } catch {
    return void 0;
  }
}
function capPrMarkdownBody(markdown, maxChars = 62e3) {
  if (markdown.length <= maxChars) return markdown;
  return `${markdown.slice(0, maxChars - 220)}

_\u2026truncated for GitHub review body limit._
`;
}
function resolvePrRuntimeMode(cliMode) {
  const a = cliMode?.trim().toLowerCase();
  if (a === "attack" || a === "attack-ai" || a === "review") return a;
  const b = ghActionInput("runtime-mode")?.trim().toLowerCase();
  if (b === "attack" || b === "attack-ai" || b === "review") return b;
  const c = ghActionInput("mode")?.trim().toLowerCase();
  if (c === "attack" || c === "attack-ai" || c === "review") return c;
  return "review";
}
function resolveRuntimeWallSeconds(cliValue) {
  if (cliValue !== void 0 && Number.isFinite(cliValue)) {
    return Math.min(7200, Math.max(30, Math.trunc(cliValue)));
  }
  const g = ghActionInput("runtime-timeout-seconds");
  if (g) {
    const n = parseInt(g, 10);
    if (Number.isFinite(n)) return Math.min(7200, Math.max(30, n));
  }
  return 900;
}
function resolvePentestWallSeconds(cli) {
  if (cli !== void 0 && Number.isFinite(cli)) {
    return Math.min(7200, Math.max(30, Math.trunc(cli)));
  }
  const g = process.env.SECURE_REVIEW_PENTEST_TIMEOUT_SECONDS;
  if (g) {
    const n = parseInt(g.trim(), 10);
    if (Number.isFinite(n)) return Math.min(7200, Math.max(30, n));
  }
  return 900;
}
function parseDynamicChecks(raw) {
  const checks = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (checks.length === 0) {
    throw new InvalidArgumentError("checks must be a comma-separated list");
  }
  return checks.map((check) => {
    const parsed = DynamicCheck.safeParse(check);
    if (!parsed.success) {
      throw new InvalidArgumentError(
        `unknown dynamic check '${check}' (valid: headers,cookies,cors,sensitive_paths)`
      );
    }
    return parsed.data;
  });
}
async function readPackageVersion() {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(here, "..", "package.json"),
    resolve(here, "..", "..", "package.json")
  ];
  for (const candidate of candidates) {
    try {
      const raw = JSON.parse(await readFile(candidate, "utf8"));
      const PackageSchema = z.object({ name: z.string().optional(), version: z.string().optional() });
      const meta = PackageSchema.parse(raw);
      if ((meta.name === "secure-review-runtime" || meta.name === "secure-review") && meta.version) {
        return meta.version;
      }
    } catch {
    }
  }
  return "0.0.0";
}
function applyMaxCostOverride(config, value) {
  if (value === void 0) return;
  config.gates.max_cost_usd = value;
}
var GithubPrEventSchema = z.object({
  pull_request: z.object({
    number: z.number(),
    head: z.object({
      sha: z.string(),
      repo: z.object({ fork: z.boolean().optional() }).optional()
    }),
    base: z.object({ sha: z.string(), ref: z.string() })
  }).optional(),
  repository: z.object({
    owner: z.object({ login: z.string().optional() }).optional(),
    name: z.string().optional()
  }).optional()
});
async function main() {
  const version = await readPackageVersion();
  const program = new Command();
  program.name("secure-review-runtime").description("Runtime Layer-4 probes: attack, attack-ai, pr-runtime (live targets + optional scanners)").version(version).option("-q, --quiet", "suppress info output", false).option("-v, --verbose", "enable debug output", false).hook("preAction", (thisCommand) => {
    const opts = thisCommand.opts();
    if (opts.quiet) setQuiet(true);
    if (opts.verbose) setVerbose(true);
  });
  program.command("attack").description("Run Layer 4 deterministic runtime probes against a live target URL.").argument("[path]", "project root for config resolution", ".").option("-c, --config <file>", "config file", ".secure-review.yml").option("-o, --output-dir <dir>", "output directory", "./reports").option("--target-url <url>", "runtime target URL (overrides dynamic.target_url)").option("--checks <list>", "comma-separated dynamic checks: headers,cookies,cors,sensitive_paths", parseDynamicChecks).option("--timeout-seconds <n>", "per-request timeout in seconds", parseTimeoutSeconds).option(
    "-H, --header <pair>",
    "HTTP header Name: value on every probe (repeatable); merged over dynamic.auth_headers",
    (value, prev) => [...prev, value],
    []
  ).option(
    "--pentest-scanners <list>",
    "after built-in probes run ZAP baseline (Docker) and/or nuclei \u2014 comma: zap-baseline,nuclei"
  ).option(
    "--browser-login-script <path>",
    'Node script printing final stdout line JSON { "headers": {} } (merged before probes + scanners)'
  ).option(
    "--pentest-timeout-seconds <n>",
    "wall-clock budget for ZAP/Nuclei only (30\u20137200; default 900)",
    parseRuntimePrTimeoutSeconds
  ).option("--task-id <id>", "task identifier for evidence JSON", "unknown").option("--run <n>", "run number", "1").action(
    async (path, opts) => {
      try {
        const wallStarted = Date.now();
        const { config } = await loadConfig(opts.config);
        const rootResolved = resolve(path);
        let authHeaders = mergeAuthHeaders(
          config.dynamic.auth_headers,
          mergeAuthHeaders(
            parseAuthHeadersJson(process.env.SECURE_REVIEW_AUTH_HEADERS_JSON),
            authHeadersFromCliList(opts.header)
          )
        );
        if (opts.browserLoginScript) {
          const hook = runBrowserLoginScript(opts.browserLoginScript, rootResolved);
          authHeaders = mergeAuthHeaders(authHeaders, hook.headers);
        }
        const output = await runAttackMode({
          root: rootResolved,
          config,
          targetUrl: opts.targetUrl,
          checks: opts.checks,
          timeoutSeconds: opts.timeoutSeconds,
          authHeaders: authHeaders ?? void 0
        });
        const stamp = timestamp();
        const mdPath = outputPath(
          config.output.report,
          DEFAULT_OUTPUT.report,
          opts.outputDir,
          `attack-${stamp}.md`,
          stamp
        );
        const jsonPath = outputPath(
          config.output.findings,
          DEFAULT_OUTPUT.findings,
          opts.outputDir,
          `attack-${stamp}.json`,
          stamp
        );
        const kinds = parsePentestScannerList(opts.pentestScanners);
        let appendix = "";
        let scannerFindings = [];
        if (kinds.length > 0) {
          log.info(
            `External scanners: ${kinds.join(", ")} (wall budget ${resolvePentestWallSeconds(opts.pentestTimeoutSeconds)}s)`
          );
          const wallMs = resolvePentestWallSeconds(opts.pentestTimeoutSeconds) * 1e3;
          const pentest = await runCliPentestScanners(kinds, output.targetUrl, wallMs);
          appendix = pentest.appendixMarkdown;
          scannerFindings = pentest.findings;
        }
        const mergedFindings = [...output.findings, ...scannerFindings];
        const mergedBreakdown = severityBreakdown(mergedFindings);
        const scannerGate = evaluateRuntimePrGate(mergedFindings, config.dynamic.gates);
        const gateBlockedFinal = output.gateBlocked || scannerGate.blocked;
        const gateReasonsFinal = [...output.gateReasons];
        for (const r of scannerGate.reasons) {
          if (!gateReasonsFinal.includes(r)) gateReasonsFinal.push(r);
        }
        await writeFileSafe(
          mdPath,
          renderAttackReport(output) + (appendix ? `

---

## External scanners (ZAP / Nuclei)
${appendix}` : "")
        );
        const evidence = renderAttackEvidence(output, {
          taskId: opts.taskId,
          run: Number(opts.run),
          modelVersion: "dynamic-runtime",
          reviewerNames: ["dynamic"]
        });
        const evidenceOut = {
          ...evidence,
          findings: mergedFindings,
          runtime_findings: mergedFindings,
          findings_by_severity_initial: mergedBreakdown,
          findings_by_severity_after_fix: mergedBreakdown,
          total_findings_initial: mergedFindings.length,
          total_findings_after_fix: mergedFindings.length,
          gate_blocked: gateBlockedFinal,
          gate_reasons: gateReasonsFinal,
          notes: gateBlockedFinal ? `Gate blocked: ${gateReasonsFinal.join("; ")}` : evidence.notes
        };
        await writeFileSafe(jsonPath, JSON.stringify(evidenceOut, null, 2));
        log.success(`Report:    ${mdPath}`);
        log.success(`Findings:  ${jsonPath}`);
        const wallClockS = (Date.now() - wallStarted) / 1e3;
        log.info(
          `Runtime findings: ${output.findings.length} (+ ${scannerFindings.length} from scanners)  Gate: ${gateBlockedFinal ? "BLOCKED" : "passed"}  Duration: ${wallClockS.toFixed(1)}s`
        );
        if (gateBlockedFinal) process.exit(2);
      } catch (err) {
        log.error(err instanceof Error ? err.message : String(err));
        process.exit(1);
      }
    }
  );
  program.command("attack-ai").description("Run authorized AI-planned, same-origin runtime probes against a live target URL.").argument("[path]", "project root for source context and config resolution", ".").option("-c, --config <file>", "config file", ".secure-review.yml").option("-o, --output-dir <dir>", "output directory", "./reports").option("--target-url <url>", "runtime target URL (overrides dynamic.target_url)").option("--timeout-seconds <n>", "per-request timeout in seconds", parseTimeoutSeconds).option("--max-requests <n>", "maximum total runtime HTTP requests", parseMaxRequests).option("--max-crawl-pages <n>", "maximum same-origin pages to crawl", parseMaxCrawlPages).option("--rate-limit-per-second <n>", "maximum HTTP request rate", parseRateLimit).option("--attack-provider <p>", "override attacker LLM provider (anthropic|openai|google)", parseAttackProvider).option("--attack-model <id>", "override attacker model id (defaults from dynamic.attacker or writer)").option("--attack-skill <path>", "override attacker skill path (relative to config file or absolute)").option(
    "-H, --header <pair>",
    "HTTP header Name: value on crawl/probes (repeatable); merged over dynamic.auth_headers",
    (value, prev) => [...prev, value],
    []
  ).option(
    "--pentest-scanners <list>",
    "after attack-ai run ZAP baseline (Docker) and/or nuclei \u2014 comma: zap-baseline,nuclei"
  ).option(
    "--browser-login-script <path>",
    'Node script printing final stdout line JSON { "headers": {} }'
  ).option(
    "--pentest-timeout-seconds <n>",
    "wall-clock budget for ZAP/Nuclei only (30\u20137200; default 900)",
    parseRuntimePrTimeoutSeconds
  ).option(
    "--enable-runtime-attacks",
    "opt in to live runtime probing (overrides config dynamic.enabled=false). Required when dynamic.enabled is not true.",
    false
  ).option("--task-id <id>", "task identifier for evidence JSON", "unknown").option("--run <n>", "run number", "1").action(
    async (path, opts) => {
      try {
        const wallStarted = Date.now();
        const { config, configDir } = await loadConfig(opts.config);
        const gate = isRuntimeAttackAllowed(config, opts.enableRuntimeAttacks);
        if (!gate.allowed) {
          log.warn(`attack-ai skipped: ${gate.reason}`);
          return;
        }
        const env = loadEnv();
        const root = resolve(path);
        let authHeaders = mergeAuthHeaders(
          config.dynamic.auth_headers,
          mergeAuthHeaders(
            parseAuthHeadersJson(process.env.SECURE_REVIEW_AUTH_HEADERS_JSON),
            authHeadersFromCliList(opts.header)
          )
        );
        if (opts.browserLoginScript) {
          authHeaders = mergeAuthHeaders(authHeaders, runBrowserLoginScript(opts.browserLoginScript, root).headers);
        }
        const output = await runAttackAiMode({
          root,
          config,
          configDir,
          env,
          targetUrl: opts.targetUrl,
          timeoutSeconds: opts.timeoutSeconds,
          maxRequests: opts.maxRequests,
          maxCrawlPages: opts.maxCrawlPages,
          rateLimitPerSecond: opts.rateLimitPerSecond,
          attackerProvider: opts.attackProvider,
          attackerModel: opts.attackModel,
          attackerSkillPath: opts.attackSkill,
          authHeaders: authHeaders ?? void 0
        });
        const stamp = timestamp();
        const mdPath = outputPath(
          config.output.report,
          DEFAULT_OUTPUT.report,
          opts.outputDir,
          `attack-ai-${stamp}.md`,
          stamp
        );
        const jsonPath = outputPath(
          config.output.findings,
          DEFAULT_OUTPUT.findings,
          opts.outputDir,
          `attack-ai-${stamp}.json`,
          stamp
        );
        const kinds = parsePentestScannerList(opts.pentestScanners);
        let appendix = "";
        let scannerFindings = [];
        if (kinds.length > 0) {
          log.info(
            `External scanners: ${kinds.join(", ")} (wall budget ${resolvePentestWallSeconds(opts.pentestTimeoutSeconds)}s)`
          );
          const wallMs = resolvePentestWallSeconds(opts.pentestTimeoutSeconds) * 1e3;
          const pentest = await runCliPentestScanners(kinds, output.targetUrl, wallMs);
          appendix = pentest.appendixMarkdown;
          scannerFindings = pentest.findings;
        }
        const mergedFindings = [...output.findings, ...scannerFindings];
        const mergedBreakdown = severityBreakdown(mergedFindings);
        const scannerGate = evaluateRuntimePrGate(mergedFindings, config.dynamic.gates);
        const gateBlockedFinal = output.gateBlocked || scannerGate.blocked;
        const gateReasonsFinal = [...output.gateReasons];
        for (const r of scannerGate.reasons) {
          if (!gateReasonsFinal.includes(r)) gateReasonsFinal.push(r);
        }
        await writeFileSafe(
          mdPath,
          renderAttackAiReport(output) + (appendix ? `

---

## External scanners (ZAP / Nuclei)
${appendix}` : "")
        );
        const evidence = renderAttackAiEvidence(output, {
          taskId: opts.taskId,
          run: Number(opts.run),
          modelVersion: `${output.attacker.provider}/${output.attacker.model}`,
          reviewerNames: ["attack-ai"]
        });
        const evidenceOut = {
          ...evidence,
          findings: mergedFindings,
          runtime_findings: mergedFindings,
          findings_by_severity_initial: mergedBreakdown,
          findings_by_severity_after_fix: mergedBreakdown,
          total_findings_initial: mergedFindings.length,
          total_findings_after_fix: mergedFindings.length,
          gate_blocked: gateBlockedFinal,
          gate_reasons: gateReasonsFinal,
          notes: gateBlockedFinal ? `Gate blocked: ${gateReasonsFinal.join("; ")}` : evidence.notes
        };
        await writeFileSafe(jsonPath, JSON.stringify(evidenceOut, null, 2));
        log.success(`Report:    ${mdPath}`);
        log.success(`Findings:  ${jsonPath}`);
        const wallClockS = (Date.now() - wallStarted) / 1e3;
        log.info(
          `AI attack findings: ${output.findings.length} (+ ${scannerFindings.length} from scanners)  Probes: ${output.probes.length}  Gate: ${gateBlockedFinal ? "BLOCKED" : "passed"}  Duration: ${wallClockS.toFixed(1)}s  Cost: $${output.totalCostUSD.toFixed(3)}`
        );
        if (gateBlockedFinal) process.exit(2);
      } catch (err) {
        log.error(err instanceof Error ? err.message : String(err));
        process.exit(1);
      }
    }
  );
  program.command("pr-runtime").description(
    "GitHub Action entrypoint \u2014 runtime attack / attack-ai + optional ZAP/Nuclei (Markdown PR comment)."
  ).option("-c, --config <file>", "config file", ".secure-review.yml").option("--autofix", "deprecated no-op when running static review mode", false).option("--max-cost-usd <n>", "override cost cap (static review)", parseMaxCostUsd).option(
    "--runtime-mode <mode>",
    "review | attack | attack-ai (or set INPUT_RUNTIME_MODE / INPUT_MODE)"
  ).option("--target-url <url>", "live app URL for attack / attack-ai / external scanners").option(
    "--pentest-scanners <list>",
    "comma-separated zap-baseline and/or nuclei (requires --target-url)"
  ).option(
    "--browser-login-script <path>",
    'Node script printing one JSON line { "headers": { ... } } before scans'
  ).option(
    "--runtime-timeout-seconds <n>",
    "probe + scanner wall time (30\u20137200s)",
    parseRuntimePrTimeoutSeconds
  ).option(
    "--enable-runtime-attacks",
    "opt in to live runtime probing on every PR (overrides config dynamic.enabled=false). Required for attack / attack-ai modes when dynamic.enabled is not true.",
    false
  ).action(
    async (opts) => {
      try {
        const { config, configDir } = await loadConfig(opts.config);
        const env = loadEnv();
        applyMaxCostOverride(config, opts.maxCostUsd);
        const runtimeMode = resolvePrRuntimeMode(opts.runtimeMode);
        if (runtimeMode === "review" && opts.autofix) {
          log.warn("PR autofix mode is deprecated and a no-op; running static review.");
        }
        const legacyMode = ghActionInput("mode")?.trim().toLowerCase();
        if (legacyMode === "fix" && runtimeMode === "review" && !ghActionInput("runtime-mode") && !opts.runtimeMode) {
          log.warn("INPUT mode=fix is deprecated; using static multi-model review.");
        }
        const eventPath = process.env.GITHUB_EVENT_PATH;
        if (!eventPath)
          throw new Error("GITHUB_EVENT_PATH not set \u2014 `pr-runtime` subcommand requires GitHub Actions context");
        const rawEvent = JSON.parse(await readFile(eventPath, "utf8"));
        const eventParseResult = GithubPrEventSchema.safeParse(rawEvent);
        if (!eventParseResult.success) {
          throw new Error(`Invalid GitHub event payload: ${eventParseResult.error.message}`);
        }
        const event = eventParseResult.data;
        if (!event.pull_request) throw new Error("Event is not a pull_request event");
        const pr = event.pull_request;
        if (pr.head.repo?.fork) {
          log.warn("PR is from a fork; secrets not exposed. Skipping.");
          return;
        }
        const owner = event.repository?.owner?.login;
        const repo = event.repository?.name;
        if (!owner || !repo) throw new Error("Could not determine owner/repo from event payload");
        const token = env.GITHUB_TOKEN;
        if (!token) throw new Error("GITHUB_TOKEN is not set");
        log.info(`PR #${pr.number} \xB7 runtime mode: ${runtimeMode}`);
        const prPostBase = {
          owner,
          repo,
          prNumber: pr.number,
          commitSha: pr.head.sha,
          token
        };
        if (runtimeMode === "review") {
          log.warn(
            "Static multi-model PR review is implemented by `secure-review pr` / the core GitHub Action. This runtime action supports attack / attack-ai only. Exiting so CI does not pass silently."
          );
          process.exit(1);
        }
        const enableRuntimeAttacks = opts.enableRuntimeAttacks === true || parseBooleanFlag(ghActionInput("enable-runtime-attacks"));
        const gate = isRuntimeAttackAllowed(config, enableRuntimeAttacks);
        if (!gate.allowed) {
          log.warn(`pr-runtime ${runtimeMode} skipped: ${gate.reason}`);
          return;
        }
        const targetUrl = opts.targetUrl?.trim() || ghActionInput("target-url") || config.dynamic.target_url;
        if (!targetUrl) {
          throw new Error(
            "`attack` / `attack-ai` PR mode requires `target-url` (Action input, --target-url, or dynamic.target_url)"
          );
        }
        const wallSec = resolveRuntimeWallSeconds(opts.runtimeTimeoutSeconds);
        const timeoutWallMs = wallSec * 1e3;
        const attackProbeSec = Math.min(600, wallSec);
        const scannerListRaw = opts.pentestScanners ?? ghActionInput("pentest-scanners");
        const browserScript = opts.browserLoginScript ?? ghActionInput("browser-login-script");
        let authHeaders = mergeAuthHeaders(
          config.dynamic.auth_headers,
          mergeAuthHeaders(
            parseAuthHeadersJson(process.env.SECURE_REVIEW_AUTH_HEADERS_JSON),
            parseAuthHeadersJson(ghActionInput("auth-headers-json"))
          )
        );
        if (browserScript) {
          const hook = runBrowserLoginScript(browserScript, process.cwd(), Math.min(timeoutWallMs, 12e4));
          authHeaders = mergeAuthHeaders(authHeaders, hook.headers);
        }
        const aggregateFindings = [];
        let modeGateBlocked = false;
        let body = `## Runtime security \u2014 \`${runtimeMode}\`

**Target:** \`${targetUrl}\`

`;
        if (runtimeMode === "attack") {
          const attackOut = await runAttackMode({
            root: process.cwd(),
            config,
            targetUrl,
            timeoutSeconds: attackProbeSec,
            authHeaders: authHeaders ?? void 0
          });
          modeGateBlocked = attackOut.gateBlocked;
          aggregateFindings.push(...attackOut.findings);
          body += renderAttackReport(attackOut);
        } else {
          const aiOut = await runAttackAiMode({
            root: process.cwd(),
            config,
            configDir,
            env,
            targetUrl,
            timeoutSeconds: attackProbeSec,
            authHeaders: authHeaders ?? void 0
          });
          modeGateBlocked = aiOut.gateBlocked;
          aggregateFindings.push(...aiOut.findings);
          body += renderAttackAiReport(aiOut);
          body += `
_Cost (attack planner): $${aiOut.totalCostUSD.toFixed(3)}_
`;
        }
        const kinds = parsePentestScannerList(scannerListRaw);
        if (kinds.length > 0) {
          const pentest = await runCliPentestScanners(kinds, targetUrl, timeoutWallMs);
          body += pentest.appendixMarkdown;
          aggregateFindings.push(...pentest.findings);
        }
        body += `
<sub>secure-review-runtime \xB7 Layer 4 + optional external scanners</sub>`;
        await postPrMarkdownReview({
          ...prPostBase,
          bodyMarkdown: capPrMarkdownBody(body)
        });
        const combinedGate = evaluateRuntimePrGate(aggregateFindings, config.dynamic.gates);
        if (modeGateBlocked || combinedGate.blocked) {
          log.error(
            `Runtime gate blocked: ${[...modeGateBlocked ? ["built-in dynamic gate"] : [], ...combinedGate.reasons].join("; ")}`
          );
          process.exit(2);
        }
      } catch (err) {
        log.error(err instanceof Error ? err.message : String(err));
        process.exit(1);
      }
    }
  );
  const argv = [...process.argv];
  const inRunner = process.env.GITHUB_ACTIONS === "true";
  const hasSubcommand = argv.slice(2).some(
    (a) => ["attack", "attack-ai", "pr-runtime", "help"].includes(a)
  );
  if (inRunner && !hasSubcommand) {
    const mode = (process.env.INPUT_MODE ?? "review").toLowerCase();
    argv.push("pr-runtime");
    if (mode === "fix") argv.push("--autofix");
    const configInput = process.env.INPUT_CONFIG;
    if (configInput) argv.push("--config", configInput);
    const maxCostInput = process.env.INPUT_MAX_COST_USD;
    if (maxCostInput) argv.push("--max-cost-usd", maxCostInput);
    const runtimeModeInput = process.env.INPUT_RUNTIME_MODE;
    if (runtimeModeInput) argv.push("--runtime-mode", runtimeModeInput);
    const targetUrlInput = process.env.INPUT_TARGET_URL;
    if (targetUrlInput) argv.push("--target-url", targetUrlInput);
    const timeoutInput = process.env.INPUT_RUNTIME_TIMEOUT_SECONDS;
    if (timeoutInput) argv.push("--runtime-timeout-seconds", timeoutInput);
    if (parseBooleanFlag(process.env.INPUT_ENABLE_RUNTIME_ATTACKS)) {
      argv.push("--enable-runtime-attacks");
    }
  }
  await program.parseAsync(argv);
}
function isDirectExecution() {
  if (!process.argv[1]) return false;
  const modulePath = fileURLToPath(import.meta.url);
  try {
    return realpathSync(resolve(process.argv[1])) === realpathSync(modulePath);
  } catch {
    return resolve(process.argv[1]) === modulePath;
  }
}
if (isDirectExecution()) {
  main().catch((err) => {
    log.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
export {
  authHeadersFromCliList,
  parseAttackProvider,
  parseAuthHeaderLine,
  parseAuthHeadersJson,
  parseDynamicChecks,
  parseMaxCostUsd,
  parseMaxCrawlPages,
  parseMaxIterations,
  parseMaxRequests,
  parseMaxWallTimeMinutes,
  parseRateLimit,
  parseRuntimePrTimeoutSeconds,
  parseTimeoutSeconds
};
//# sourceMappingURL=cli.js.map