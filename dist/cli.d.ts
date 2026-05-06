#!/usr/bin/env node
import { DynamicCheck } from 'secure-review';

declare function parseMaxIterations(raw: string): number;
declare function parseMaxCostUsd(raw: string): number;
declare function parseMaxWallTimeMinutes(raw: string): number;
declare function parseTimeoutSeconds(raw: string): number;
/** PR/runtime job budget for scanners + probes (GitHub Actions can run longer single steps). */
declare function parseRuntimePrTimeoutSeconds(raw: string): number;
declare function parseMaxRequests(raw: string): number;
declare function parseMaxCrawlPages(raw: string): number;
declare function parseRateLimit(raw: string): number;
declare function parseAttackProvider(raw: string): "anthropic" | "openai" | "google";
/** Parse `Name: value` headers for authenticated runtime HTTP probes (repeatable CLI `-H`). */
declare function parseAuthHeaderLine(raw: string): {
    name: string;
    value: string;
};
declare function authHeadersFromCliList(lines: string[] | undefined): Record<string, string> | undefined;
/**
 * JSON object of header names → values (CI secret / env). Values must be
 * strings.
 *
 * Surfaces parse problems via `log.warn` rather than silently dropping the
 * input — previously a malformed JSON or non-string value made probes run
 * unauthenticated with no feedback to the operator.
 */
declare function parseAuthHeadersJson(raw: string | undefined): Record<string, string> | undefined;
declare function parseDynamicChecks(raw: string): DynamicCheck[];
/**
 * Pure function (no I/O, no side effects) that wraps the argv-shim used
 * to invoke this CLI from a GitHub Actions job. When `GITHUB_ACTIONS=true`
 * and no subcommand is present in argv, append `pr-runtime` and translate
 * each documented `INPUT_*` env var into its corresponding CLI flag.
 *
 * Exported so tests can verify the wiring without spawning Node.
 */
declare function buildGhActionArgv(inputArgv: readonly string[], env: NodeJS.ProcessEnv): string[];

export { authHeadersFromCliList, buildGhActionArgv, parseAttackProvider, parseAuthHeaderLine, parseAuthHeadersJson, parseDynamicChecks, parseMaxCostUsd, parseMaxCrawlPages, parseMaxIterations, parseMaxRequests, parseMaxWallTimeMinutes, parseRateLimit, parseRuntimePrTimeoutSeconds, parseTimeoutSeconds };
