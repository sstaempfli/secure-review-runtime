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
/** Parse `Name: value` headers for authenticated Layer 4 probes (repeatable CLI `-H`). */
declare function parseAuthHeaderLine(raw: string): {
    name: string;
    value: string;
};
declare function authHeadersFromCliList(lines: string[] | undefined): Record<string, string> | undefined;
/** JSON object of header names → values (CI secret / env). Values must be strings. */
declare function parseAuthHeadersJson(raw: string | undefined): Record<string, string> | undefined;
declare function parseDynamicChecks(raw: string): DynamicCheck[];

export { authHeadersFromCliList, parseAttackProvider, parseAuthHeaderLine, parseAuthHeadersJson, parseDynamicChecks, parseMaxCostUsd, parseMaxCrawlPages, parseMaxIterations, parseMaxRequests, parseMaxWallTimeMinutes, parseRateLimit, parseRuntimePrTimeoutSeconds, parseTimeoutSeconds };
