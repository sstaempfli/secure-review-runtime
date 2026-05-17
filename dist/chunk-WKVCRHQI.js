// src/modes/attack.ts
import { severityBreakdown } from "secure-review";
import { log } from "secure-review";
import { mergeAuthHeaders } from "secure-review";
var EVIL_ORIGIN = "https://secure-review.invalid";
async function runAttackMode(input) {
  const started = Date.now();
  const config = input.config.dynamic;
  const targetUrl = normalizeTargetUrl(input.targetUrl ?? config.target_url);
  const timeoutMs = (input.timeoutSeconds ?? config.timeout_seconds) * 1e3;
  const checks = input.checks ?? config.checks;
  log.header(`Attack mode \u2014 ${targetUrl}`);
  log.info(`Checks: ${checks.join(", ")} \xB7 timeout ${(timeoutMs / 1e3).toFixed(0)}s`);
  const findings = [];
  const results = [];
  let nextId = 1;
  const authHeaders = mergeAuthHeaders(config.auth_headers, input.authHeaders);
  const addFinding = (finding) => {
    findings.push({
      ...finding,
      id: `D-${String(nextId).padStart(2, "0")}`,
      reportedBy: ["dynamic"],
      confidence: 1
    });
    nextId += 1;
  };
  if (config.healthcheck_url) {
    const result = await runHealthcheck(config.healthcheck_url, timeoutMs, authHeaders);
    results.push(result);
    if (!result.ok) {
      throw new Error(`Healthcheck failed for ${config.healthcheck_url}: ${result.error ?? `HTTP ${result.status}`}`);
    }
  }
  for (const check of checks) {
    const before = findings.length;
    const result = await runCheck(check, targetUrl, timeoutMs, config, addFinding, authHeaders);
    results.push(...result);
    const added = findings.length - before;
    log.info(`  ${check}: ${added} finding${added === 1 ? "" : "s"}`);
  }
  assertAnyProbeSucceeded(results, targetUrl);
  const gate = evaluateDynamicGates(findings, config);
  return {
    targetUrl,
    checks: results,
    findings,
    breakdown: severityBreakdown(findings),
    gateBlocked: gate.blocked,
    gateReasons: gate.reasons,
    totalDurationMs: Date.now() - started
  };
}
async function runCheck(check, targetUrl, timeoutMs, config, addFinding, authHeaders) {
  if (check === "headers") return [await checkHeaders(targetUrl, timeoutMs, addFinding, authHeaders)];
  if (check === "cookies") return [await checkCookies(targetUrl, timeoutMs, addFinding, authHeaders)];
  if (check === "cors") return [await checkCors(targetUrl, timeoutMs, addFinding, authHeaders)];
  return checkSensitivePaths(targetUrl, timeoutMs, config.sensitive_paths, addFinding, authHeaders);
}
async function runHealthcheck(url, timeoutMs, authHeaders) {
  const started = Date.now();
  try {
    const res = await probe(url, { timeoutMs }, authHeaders);
    return {
      check: "healthcheck",
      url,
      method: "GET",
      status: res.status,
      ok: res.status >= 200 && res.status < 400,
      durationMs: res.durationMs,
      evidence: { responseHeaders: headersObject(res.headers), bodySnippet: res.bodySnippet },
      error: res.status >= 200 && res.status < 400 ? void 0 : `HTTP ${res.status}`
    };
  } catch (err) {
    return errorResult("healthcheck", url, "GET", Date.now() - started, err);
  }
}
async function checkHeaders(targetUrl, timeoutMs, addFinding, authHeaders) {
  const started = Date.now();
  try {
    const res = await probe(targetUrl, { timeoutMs }, authHeaders);
    const headers = lowerHeaders(res.headers);
    const isHttps = new URL(targetUrl).protocol === "https:";
    if (!headers.has("content-security-policy")) {
      addFinding(dynamicFinding("MEDIUM", targetUrl, "Missing Content-Security-Policy header", "The response does not include a Content-Security-Policy header, reducing protection against XSS and content injection.", "Add a restrictive Content-Security-Policy header appropriate for the application.", "CWE-1021"));
    }
    if (!headers.has("x-frame-options") && !frameAncestorsPresent(headers.get("content-security-policy"))) {
      addFinding(dynamicFinding("MEDIUM", targetUrl, "Missing clickjacking protection", "The response lacks X-Frame-Options and a CSP frame-ancestors directive, allowing framing by another origin.", "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.", "CWE-1021"));
    }
    if (headers.get("x-content-type-options")?.toLowerCase() !== "nosniff") {
      addFinding(dynamicFinding("LOW", targetUrl, "Missing X-Content-Type-Options: nosniff", "The response does not opt out of MIME sniffing.", "Set X-Content-Type-Options: nosniff on HTTP responses.", "CWE-16"));
    }
    if (isHttps && !headers.has("strict-transport-security")) {
      addFinding(dynamicFinding("LOW", targetUrl, "Missing Strict-Transport-Security header", "HTTPS responses do not include HSTS, so browsers are not instructed to require HTTPS for future requests.", "Set Strict-Transport-Security with an appropriate max-age and includeSubDomains policy.", "CWE-319"));
    }
    return successResult("headers", res, { responseHeaders: headersObject(res.headers) });
  } catch (err) {
    return errorResult("headers", targetUrl, "GET", Date.now() - started, err);
  }
}
async function checkCookies(targetUrl, timeoutMs, addFinding, authHeaders) {
  const started = Date.now();
  try {
    const res = await probe(targetUrl, { timeoutMs }, authHeaders);
    const cookies = getSetCookies(res.headers);
    for (const cookie of cookies) {
      const name = cookie.split("=", 1)[0]?.trim() || "(unnamed cookie)";
      const lower = cookie.toLowerCase();
      if (!lower.includes("httponly")) {
        addFinding(dynamicFinding("HIGH", targetUrl, `Cookie ${name} missing HttpOnly`, `Set-Cookie does not include HttpOnly: ${redactCookie(cookie)}`, "Set HttpOnly on session and authentication cookies.", "CWE-1004"));
      }
      if (new URL(targetUrl).protocol === "https:" && !lower.includes("secure")) {
        addFinding(dynamicFinding("HIGH", targetUrl, `Cookie ${name} missing Secure`, `HTTPS response sets a cookie without Secure: ${redactCookie(cookie)}`, "Set Secure on cookies sent over HTTPS.", "CWE-614"));
      }
      if (!lower.includes("samesite=")) {
        addFinding(dynamicFinding("MEDIUM", targetUrl, `Cookie ${name} missing SameSite`, `Set-Cookie does not include SameSite: ${redactCookie(cookie)}`, "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.", "CWE-352"));
      }
    }
    return successResult("cookies", res, { setCookieCount: cookies.length, cookies: cookies.map(redactCookie) });
  } catch (err) {
    return errorResult("cookies", targetUrl, "GET", Date.now() - started, err);
  }
}
async function checkCors(targetUrl, timeoutMs, addFinding, authHeaders) {
  const started = Date.now();
  try {
    const res = await probe(
      targetUrl,
      {
        timeoutMs,
        headers: { Origin: EVIL_ORIGIN, "Access-Control-Request-Method": "GET" }
      },
      authHeaders
    );
    const allowOrigin = res.headers.get("access-control-allow-origin")?.trim();
    const allowCreds = res.headers.get("access-control-allow-credentials")?.trim().toLowerCase();
    if (allowOrigin === "*") {
      addFinding(dynamicFinding(allowCreds === "true" ? "CRITICAL" : "HIGH", targetUrl, "CORS allows wildcard origin", `The response to an untrusted Origin returned Access-Control-Allow-Origin: *${allowCreds === "true" ? " and credentials=true" : ""}.`, "Restrict Access-Control-Allow-Origin to trusted origins only.", "CWE-942"));
    } else if (allowOrigin === EVIL_ORIGIN) {
      addFinding(dynamicFinding(allowCreds === "true" ? "CRITICAL" : "HIGH", targetUrl, "CORS reflects untrusted origin", `The response reflected the untrusted Origin ${EVIL_ORIGIN}${allowCreds === "true" ? " with credentials enabled" : ""}.`, "Validate Origin against an allow-list before reflecting it.", "CWE-942"));
    }
    return successResult("cors", res, {
      requestHeaders: { Origin: EVIL_ORIGIN, "Access-Control-Request-Method": "GET" },
      responseHeaders: headersObject(res.headers)
    });
  } catch (err) {
    return errorResult("cors", targetUrl, "GET", Date.now() - started, err);
  }
}
async function checkSensitivePaths(targetUrl, timeoutMs, paths, addFinding, authHeaders) {
  const results = [];
  for (const path of paths) {
    const url = new URL(path, ensureTrailingSlash(targetUrl)).toString();
    const started = Date.now();
    try {
      const res = await probe(url, { timeoutMs }, authHeaders);
      const exposed = res.status >= 200 && res.status < 300 && res.bodySnippet.trim().length > 0 && !isLikelySpaFallback(path, res);
      if (exposed) {
        addFinding(dynamicFinding(sensitivePathSeverity(path), url, `Sensitive path exposed: ${path}`, `Runtime probe fetched ${path} with HTTP ${res.status}. Response snippet: ${res.bodySnippet || "(empty)"}`, "Remove the file from the deployed artifact or block this path at the web server/router.", "CWE-200"));
      }
      results.push(successResult("sensitive_paths", res, { path, exposed, bodySnippet: res.bodySnippet }));
    } catch (err) {
      results.push(errorResult("sensitive_paths", url, "GET", Date.now() - started, err, { path }));
    }
  }
  return results;
}
async function probe(url, opts, authDefaults) {
  const started = Date.now();
  const headers = mergeAuthHeaders(authDefaults, opts.headers);
  const res = await fetch(url, {
    method: "GET",
    redirect: "manual",
    ...headers ? { headers } : {},
    signal: AbortSignal.timeout(opts.timeoutMs)
  });
  const text = await safeText(res);
  return {
    url,
    method: "GET",
    status: res.status,
    headers: res.headers,
    bodySnippet: redactBody(text).slice(0, 500),
    durationMs: Date.now() - started
  };
}
async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
function dynamicFinding(severity, file, title, description, remediation, cwe) {
  return { severity, cwe, file, lineStart: 0, lineEnd: 0, title, description, remediation };
}
function evaluateDynamicGates(findings, config) {
  const reasons = [];
  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const high = findings.filter((f) => f.severity === "HIGH").length;
  if (config.gates.block_on_confirmed_critical && critical > 0) {
    reasons.push(`${critical} confirmed CRITICAL runtime finding${critical === 1 ? "" : "s"}`);
  }
  if (config.gates.block_on_confirmed_high && high > 0) {
    reasons.push(`${high} confirmed HIGH runtime finding${high === 1 ? "" : "s"}`);
  }
  return { blocked: reasons.length > 0, reasons };
}
function normalizeTargetUrl(raw) {
  if (!raw) throw new Error("Attack target URL required. Pass --target-url or set dynamic.target_url.");
  const url = new URL(raw);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`Attack target must be http(s): ${raw}`);
  return url.toString();
}
function ensureTrailingSlash(url) {
  const u = new URL(url);
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u.toString();
}
function successResult(check, res, evidence) {
  return { check, url: res.url, method: res.method, status: res.status, ok: true, durationMs: res.durationMs, evidence };
}
function assertAnyProbeSucceeded(results, targetUrl) {
  if (results.some((result) => result.ok)) return;
  const firstError = results.find((result) => result.error)?.error ?? "no successful HTTP response";
  throw new Error(
    `Attack target was not reachable at ${targetUrl}. All runtime probes failed before receiving a response: ${firstError}`
  );
}
function errorResult(check, url, method, durationMs, err, evidence = {}) {
  return { check, url, method, ok: false, durationMs, evidence, error: err instanceof Error ? err.message : String(err) };
}
function lowerHeaders(headers) {
  const out = /* @__PURE__ */ new Map();
  headers.forEach((value, key) => out.set(key.toLowerCase(), value));
  return out;
}
function headersObject(headers) {
  const out = {};
  headers.forEach((value, key) => {
    out[key] = redactHeader(key, value);
  });
  return out;
}
function frameAncestorsPresent(csp) {
  return csp?.toLowerCase().split(";").some((part) => part.trim().startsWith("frame-ancestors")) ?? false;
}
function getSetCookies(headers) {
  const h = headers;
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  if (typeof h.raw === "function") return h.raw()["set-cookie"] ?? [];
  const single = headers.get("set-cookie");
  if (!single) return [];
  return splitCombinedSetCookie(single);
}
function splitCombinedSetCookie(header) {
  return header.split(/,(?=\s*[^;,=\s]+=[^;]+)/).map((s) => s.trim()).filter(Boolean);
}
function redactHeader(key, value) {
  if (key.toLowerCase() !== "set-cookie") return value;
  return splitCombinedSetCookie(value).map(redactCookie).join(", ");
}
function redactCookie(cookie) {
  return cookie.replace(/^([^=;]+)=([^;]*)/, (_match, name) => `${name}=<redacted>`);
}
function redactBody(body) {
  return body.replace(/([A-Z0-9_]*TOKEN[A-Z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1<redacted>").replace(/([A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1<redacted>").replace(/([A-Z0-9_]*KEY[A-Z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1<redacted>");
}
function isLikelySpaFallback(path, res) {
  const contentType = res.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("text/html")) return false;
  const body = res.bodySnippet.toLowerCase();
  if (!body.includes("<!doctype html") && !body.includes("<html")) return false;
  if (body.includes("/@vite/client") || body.includes("/@react-refresh")) return true;
  const suspiciousFilePath = /\.[a-z0-9]{2,8}$/i.test(path);
  if (suspiciousFilePath) return true;
  return body.includes('id="root"') || body.includes("id='root'") || body.includes('type="module"') || body.includes("type='module'");
}
function sensitivePathSeverity(path) {
  if (path === "/.env" || path === "/.git/config") return "CRITICAL";
  if (path.includes("config") || path.includes("debug")) return "HIGH";
  return "MEDIUM";
}

// src/pentest/playwright-crawler.ts
import { log as log2 } from "secure-review";
async function crawlWithPlaywright(input) {
  let playwright;
  try {
    const specifier = "playwright";
    playwright = await import(specifier);
  } catch {
    throw new Error(
      "Playwright is not installed.\nInstall it with:\n  npm install --save-dev playwright\n  npx playwright install chromium\nThen retry with --playwright."
    );
  }
  const origin = new URL(input.targetUrl).origin;
  log2.info("Playwright crawler \u2014 launching Chromium (headless)");
  const browser = await playwright.chromium.launch({ headless: true });
  try {
    const extraHTTPHeaders = {};
    const cookiesToAdd = [];
    for (const [name, value] of Object.entries(input.authHeaders ?? {})) {
      if (name.toLowerCase() === "cookie") {
        cookiesToAdd.push(...parseCookieHeader(value, new URL(input.targetUrl)));
      } else {
        extraHTTPHeaders[name] = value;
      }
    }
    const context = await browser.newContext({
      ...Object.keys(extraHTTPHeaders).length > 0 ? { extraHTTPHeaders } : {},
      ignoreHTTPSErrors: true
    });
    if (cookiesToAdd.length > 0) {
      await context.addCookies(cookiesToAdd);
      log2.info(`  Applied ${cookiesToAdd.length} auth cookie${cookiesToAdd.length === 1 ? "" : "s"} to browser context`);
    }
    const pages = [];
    const visited = /* @__PURE__ */ new Set();
    const queue = [input.targetUrl];
    while (queue.length > 0 && pages.length < input.maxPages) {
      const url = queue.shift();
      const normalized = normalizeForVisit(url);
      if (visited.has(normalized)) continue;
      visited.add(normalized);
      const pw = await context.newPage();
      const apiEndpoints = /* @__PURE__ */ new Set();
      pw.on("request", (req) => {
        try {
          const u = new URL(req.url());
          if (u.origin === origin && (req.resourceType() === "fetch" || req.resourceType() === "xhr")) {
            apiEndpoints.add(u.pathname + u.search);
          }
        } catch {
        }
      });
      try {
        const response = await pw.goto(url, { timeout: input.timeoutMs, waitUntil: "networkidle" }).catch(() => null);
        const finalUrl = pw.url();
        const status = response?.status() ?? 0;
        const title = await pw.title().catch(() => void 0);
        const links = await pw.$$eval(
          "a[href]",
          (anchors) => anchors.map((a) => a.href).filter(Boolean)
        ).catch(() => []);
        const forms = await pw.$$eval(
          "form",
          (formEls) => formEls.map((form) => {
            const f = form;
            return {
              action: f.action,
              method: f.method?.toUpperCase() === "POST" ? "POST" : "GET",
              fields: [...form.querySelectorAll("[name]")].map((el) => el.getAttribute("name") ?? "").filter(Boolean)
            };
          })
        ).catch(() => []);
        const sameOriginLinks2 = [];
        for (const link of links) {
          try {
            const u = new URL(link);
            if (u.origin !== origin) continue;
            u.hash = "";
            const clean = u.toString();
            const norm = normalizeForVisit(clean);
            if (!visited.has(norm) && !sameOriginLinks2.includes(clean)) {
              sameOriginLinks2.push(clean);
              if (pages.length + queue.length < input.maxPages) queue.push(clean);
            }
          } catch {
          }
        }
        pages.push({
          url: finalUrl,
          status,
          title: title || void 0,
          links: sameOriginLinks2,
          forms,
          ...apiEndpoints.size > 0 ? { apiEndpoints: [...apiEndpoints] } : {}
        });
        log2.info(
          `  Crawled [${status}] ${finalUrl}${apiEndpoints.size > 0 ? ` (+${apiEndpoints.size} XHR/fetch)` : ""}`
        );
      } catch (err) {
        log2.info(`  Skipped ${url} \u2014 ${err instanceof Error ? err.message : String(err)}`);
      } finally {
        await pw.close().catch(() => {
        });
      }
    }
    await context.close().catch(() => {
    });
    return pages;
  } finally {
    await browser.close().catch(() => {
    });
  }
}
function normalizeForVisit(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.toString().toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}
function parseCookieHeader(cookieHeader, targetUrl) {
  return cookieHeader.split(";").map((part) => {
    const eqIdx = part.indexOf("=");
    if (eqIdx <= 0) return null;
    const name = part.slice(0, eqIdx).trim();
    const value = part.slice(eqIdx + 1).trim();
    if (!name) return null;
    return { name, value, domain: targetUrl.hostname, path: "/" };
  }).filter((c) => c !== null);
}

// src/modes/attack-ai.ts
import { z } from "zod";
import { getAdapter } from "secure-review";
import { loadSkill, resolveSkillPath } from "secure-review";
import { extractJson } from "secure-review";
import { severityBreakdown as severityBreakdown2 } from "secure-review";
import { readSourceTree, serializeCodeContext } from "secure-review";
import { log as log3 } from "secure-review";
import { mergeAuthHeaders as mergeAuthHeaders2 } from "secure-review";
var MARKER_PREFIX = "secure-review-probe";
var UNTRUSTED_REDIRECT = "https://secure-review.invalid/redirect-target";
var ATTACKER_NAME = "attack-ai";
var IDOR_PROBE_ID = "9007199";
var optionalStringFromModel = z.preprocess((value) => value === null ? void 0 : value, z.string().optional());
var optionalNumberFromModel = z.preprocess((value) => value === null ? void 0 : value, z.number().int().min(0).optional());
var RawHypothesisSchema = z.object({
  id: optionalStringFromModel,
  category: z.enum(["reflected_input", "error_disclosure", "open_redirect", "path_exposure", "idor", "auth_bypass"]),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).default("MEDIUM"),
  title: z.string().min(1),
  rationale: z.string().min(1),
  path: z.string().min(1),
  method: z.preprocess((value) => value === null ? void 0 : value, z.enum(["GET", "POST"]).default("GET")),
  parameter: optionalStringFromModel,
  sourceFile: optionalStringFromModel,
  lineStart: optionalNumberFromModel,
  remediation: optionalStringFromModel
});
var HypothesisPayloadSchema = z.object({ hypotheses: z.array(RawHypothesisSchema).default([]) }).or(z.array(RawHypothesisSchema));
async function runAttackAiMode(input) {
  const started = Date.now();
  const dynamic = input.config.dynamic;
  const targetUrl = normalizeTargetUrl2(input.targetUrl ?? dynamic.target_url);
  const timeoutMs = (input.timeoutSeconds ?? dynamic.timeout_seconds) * 1e3;
  const maxRequests = input.maxRequests ?? dynamic.max_requests;
  const maxCrawlPages = input.maxCrawlPages ?? dynamic.max_crawl_pages;
  const rateLimitPerSecond = input.rateLimitPerSecond ?? dynamic.rate_limit_per_second;
  const budget = new RequestBudget(maxRequests, rateLimitPerSecond);
  const authHeaders = mergeAuthHeaders2(dynamic.auth_headers, input.authHeaders);
  log3.header(`AI attack mode \u2014 ${targetUrl}`);
  log3.info(
    `Scope: same-origin only \xB7 max ${maxRequests} requests \xB7 crawl ${maxCrawlPages} page${maxCrawlPages === 1 ? "" : "s"}`
  );
  if (dynamic.healthcheck_url) {
    const health = await safeProbe(dynamic.healthcheck_url, "GET", timeoutMs, budget, void 0, authHeaders);
    if (!health.response || health.response.status < 200 || health.response.status >= 400) {
      throw new Error(`Healthcheck failed for ${dynamic.healthcheck_url}: ${health.error ?? `HTTP ${health.response?.status}`}`);
    }
  }
  const pages = input.usePlaywright ? await crawlWithPlaywright({ targetUrl, maxPages: maxCrawlPages, timeoutMs, authHeaders }) : await crawlSameOrigin(targetUrl, timeoutMs, maxCrawlPages, budget, authHeaders);
  log3.info(`Crawled ${pages.length} page${pages.length === 1 ? "" : "s"}${input.usePlaywright ? " (Playwright)" : ""}`);
  if (pages.length === 0) {
    throw new Error(
      `AI attack target was not reachable at ${targetUrl}. No pages were crawled; verify the app is running and the URL/port are correct.`
    );
  }
  const files = await readSourceTree(input.root, 8e4);
  const mergedRef = mergeAttackerRef(input);
  const attacker = await resolveAttacker(input, mergedRef);
  const planned = await planHypotheses({
    targetUrl,
    pages,
    files,
    adapter: attacker.adapter,
    skill: attacker.skill,
    maxTokens: attacker.maxTokens
  });
  const maxCostUsd = input.config.gates.max_cost_usd;
  if (Number.isFinite(maxCostUsd) && maxCostUsd > 0 && planned.usage.costUSD > maxCostUsd) {
    throw new Error(
      `Cost cap exceeded: attack-ai planner used $${planned.usage.costUSD.toFixed(4)} but gates.max_cost_usd is $${maxCostUsd.toFixed(4)}. Aborting before probe execution. Raise gates.max_cost_usd in your config or pass --max-cost-usd to allow this run.`
    );
  }
  const hypotheses = sanitizeHypotheses(planned.hypotheses, targetUrl).slice(0, remainingProbeSlots(budget));
  log3.info(`Model proposed ${planned.hypotheses.length}; executing ${hypotheses.length} safe same-origin probe${hypotheses.length === 1 ? "" : "s"}`);
  const probes = [];
  const findings = [];
  let nextId = 1;
  for (const hypothesis of hypotheses) {
    const result = await executeHypothesis(hypothesis, targetUrl, timeoutMs, budget, authHeaders);
    probes.push(result);
    if (result.confirmed) {
      findings.push(findingFromProbe(hypothesis, result, nextId));
      nextId += 1;
    }
    if (remainingProbeSlots(budget) <= 0) break;
  }
  const gate = evaluateGates(findings, dynamic);
  return {
    targetUrl,
    pages,
    hypotheses,
    probes,
    findings,
    breakdown: severityBreakdown2(findings),
    gateBlocked: gate.blocked,
    gateReasons: gate.reasons,
    usage: planned.usage,
    totalCostUSD: planned.usage.costUSD,
    totalDurationMs: Date.now() - started,
    limits: { maxRequests, maxCrawlPages, rateLimitPerSecond },
    attacker: {
      provider: mergedRef.provider,
      model: mergedRef.model,
      skillPath: mergedRef.skill
    }
  };
}
function mergeAttackerRef(input) {
  const base = input.config.dynamic.attacker ?? input.config.writer;
  return {
    ...base,
    provider: input.attackerProvider ?? base.provider,
    model: input.attackerModel?.trim() ? input.attackerModel.trim() : base.model,
    skill: input.attackerSkillPath?.trim() ? input.attackerSkillPath.trim() : base.skill
  };
}
async function resolveAttacker(input, mergedRef) {
  const adapter = input.attackerAdapter ?? getAdapter({ provider: mergedRef.provider, model: mergedRef.model }, input.env);
  const skill = input.attackerSkill ?? await loadSkill(resolveSkillPath(mergedRef.skill, input.configDir));
  return { adapter, skill, maxTokens: mergedRef.maxTokens };
}
async function planHypotheses(input) {
  const out = await input.adapter.complete({
    system: `${input.skill}

You are the authorized AI attack planner for secure-review. Plan only non-destructive, same-origin probes against the provided target. Do not request credential theft, denial of service, persistence, shell execution, SSRF to third parties, destructive writes, or high-volume traffic.

Return JSON only:
{
  "hypotheses": [
    {
      "category": "reflected_input" | "error_disclosure" | "open_redirect" | "path_exposure" | "idor" | "auth_bypass",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "title": "short finding title if confirmed",
      "rationale": "why this is plausible from the crawl/source",
      "path": "/same-origin-path",
      "method": "GET" | "POST",
      "parameter": "single parameter name for reflected_input/error_disclosure/open_redirect (omit for idor, auth_bypass, path_exposure)",
      "sourceFile": "optional relative source file",
      "lineStart": 0,
      "remediation": "how the writer should fix it"
    }
  ]
}

Category guidance:
- reflected_input: Test a query/form parameter for unescaped reflection in the response body (XSS indicator). Requires "parameter".
- error_disclosure: Submit garbage to a parameter to elicit stack traces or DB error messages. Requires "parameter".
- open_redirect: Test a redirect parameter for open-redirect to an untrusted URL. Requires "parameter".
- path_exposure: Check whether a sensitive path (e.g. /admin, /debug, /.git) is accessible without auth.
- idor (Broken Object Level Authorization, A01:2025): Look for URL paths with numeric or UUID identifiers (e.g. /api/orders/42, /api/users/5/profile). The probe replaces the numeric segment with a different ID to test whether the server enforces per-resource ownership. No "parameter" field needed \u2014 set "path" to a URL that contains the numeric ID. Propose HIGH or CRITICAL severity; this is the class of bug most likely to expose another user's data.
- auth_bypass: Identify endpoints that should require authentication (e.g. /api/profile, /api/admin, /dashboard). The probe is sent without any session token to test whether the authentication gate is enforced. No "parameter" field needed. Propose HIGH severity.`,
    user: `Target: ${input.targetUrl}

Crawled surface:
${JSON.stringify(input.pages, null, 2)}

Note: pages may include an \`apiEndpoints\` array of XHR/fetch paths observed during rendering (Playwright mode). These are runtime API calls invisible to static analysis \u2014 prioritise them for idor and auth_bypass probes.

Source context:
${serializeCodeContext(input.files, 8e4)}

Choose the smallest set of high-signal probes. Every probe will be constrained by secure-review to same-origin GET/POST with harmless marker payloads.`,
    jsonMode: true,
    maxTokens: input.maxTokens ?? 3e3
  });
  const parsed = HypothesisPayloadSchema.parse(extractJson(out.text));
  const raw = Array.isArray(parsed) ? parsed : parsed.hypotheses;
  return {
    hypotheses: raw.map((h, index) => ({
      ...h,
      id: h.id ?? `H-${String(index + 1).padStart(2, "0")}`
    })),
    usage: out.usage
  };
}
async function crawlSameOrigin(targetUrl, timeoutMs, maxPages, budget, authHeaders) {
  const origin = new URL(targetUrl).origin;
  const queue = [targetUrl];
  const seen = /* @__PURE__ */ new Set();
  const pages = [];
  while (queue.length > 0 && pages.length < maxPages && budget.remaining() > 0) {
    const url = queue.shift();
    const normalized = normalizeUrlForVisit(url);
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    const probed = await safeProbe(normalized, "GET", timeoutMs, budget, void 0, authHeaders);
    if (!probed.response) continue;
    const res = probed.response;
    const page = parsePage(res.url, res.status, res.bodySnippet, origin);
    pages.push(page);
    for (const link of page.links) {
      if (!seen.has(link) && queue.length + pages.length < maxPages) queue.push(link);
    }
  }
  return pages;
}
async function executeHypothesis(hypothesis, targetUrl, timeoutMs, budget, authHeaders) {
  const marker = `${MARKER_PREFIX}-${hypothesis.id.toLowerCase().replace(/[^a-z0-9-]/g, "")}<sr>`;
  const started = Date.now();
  try {
    const request = buildProbeRequest(hypothesis, targetUrl, marker);
    const probeAuthHeaders = hypothesis.category === "auth_bypass" ? void 0 : authHeaders;
    const probed = await safeProbe(request.url, request.method, timeoutMs, budget, request.body, probeAuthHeaders);
    if (!probed.response) {
      return {
        hypothesisId: hypothesis.id,
        category: hypothesis.category,
        url: request.url,
        method: request.method,
        confirmed: false,
        durationMs: Date.now() - started,
        evidence: { marker },
        error: probed.error
      };
    }
    const res = probed.response;
    const confirmation = confirmHypothesis(hypothesis, res, marker);
    return {
      hypothesisId: hypothesis.id,
      category: hypothesis.category,
      url: request.url,
      method: request.method,
      status: res.status,
      confirmed: confirmation.confirmed,
      durationMs: res.durationMs,
      evidence: {
        marker,
        reason: confirmation.reason,
        responseHeaders: headersObject2(res.headers),
        bodySnippet: res.bodySnippet
      }
    };
  } catch (err) {
    return {
      hypothesisId: hypothesis.id,
      category: hypothesis.category,
      url: hypothesis.path,
      method: hypothesis.method,
      confirmed: false,
      durationMs: Date.now() - started,
      evidence: {},
      error: err instanceof Error ? err.message : String(err)
    };
  }
}
function buildProbeRequest(hypothesis, targetUrl, marker) {
  if (hypothesis.category === "idor") {
    const mutatedPath = mutateIdorPath(hypothesis.path);
    return { url: new URL(mutatedPath, targetUrl).toString(), method: hypothesis.method };
  }
  if (hypothesis.category === "auth_bypass") {
    return { url: new URL(hypothesis.path, targetUrl).toString(), method: hypothesis.method };
  }
  const url = new URL(hypothesis.path, targetUrl);
  const parameter = hypothesis.parameter ?? defaultParameter(hypothesis.category);
  const value = hypothesis.category === "open_redirect" ? UNTRUSTED_REDIRECT : marker;
  if (hypothesis.method === "POST") {
    return {
      url: url.toString(),
      method: "POST",
      body: new URLSearchParams({ [parameter]: value }).toString()
    };
  }
  url.searchParams.set(parameter, value);
  return { url: url.toString(), method: "GET" };
}
function mutateIdorPath(path) {
  const parts = path.split("/");
  for (let i = parts.length - 1; i >= 0; i--) {
    const segment = parts[i];
    if (segment !== void 0 && /^\d+$/.test(segment) && segment !== IDOR_PROBE_ID) {
      parts[i] = IDOR_PROBE_ID;
      return parts.join("/");
    }
  }
  return path;
}
async function safeProbe(url, method, timeoutMs, budget, body, authHeaders) {
  if (!await budget.tryTake()) return { error: "request budget exhausted" };
  const started = Date.now();
  try {
    const headers = mergeAuthHeaders2(
      authHeaders,
      body ? { "content-type": "application/x-www-form-urlencoded" } : void 0
    );
    const res = await fetch(url, {
      method,
      redirect: "manual",
      ...headers ? { headers } : {},
      body,
      signal: AbortSignal.timeout(timeoutMs)
    });
    const text = await safeText2(res);
    return {
      response: {
        url,
        method,
        status: res.status,
        headers: res.headers,
        bodySnippet: redactBody2(text).slice(0, 2e3),
        durationMs: Date.now() - started
      }
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}
function confirmHypothesis(hypothesis, res, marker) {
  const body = res.bodySnippet;
  if (hypothesis.category === "reflected_input") {
    const reflected = body.includes(marker);
    const escaped = body.includes(escapeHtml(marker));
    return {
      confirmed: reflected && !escaped,
      reason: reflected && !escaped ? "marker reflected unescaped in response body" : "marker not reflected unescaped"
    };
  }
  if (hypothesis.category === "error_disclosure") {
    const disclosed = /\b(stack trace|traceback|exception|syntaxerror|typeerror|referenceerror|sql error|database error)\b/i.test(body);
    return {
      confirmed: disclosed,
      reason: disclosed ? "response contains runtime/database error disclosure text" : "no error disclosure pattern observed"
    };
  }
  if (hypothesis.category === "open_redirect") {
    const location = res.headers.get("location") ?? "";
    const confirmed = res.status >= 300 && res.status < 400 && location.startsWith(UNTRUSTED_REDIRECT);
    return {
      confirmed,
      reason: confirmed ? `redirected to untrusted location ${UNTRUSTED_REDIRECT}` : "no redirect to untrusted location"
    };
  }
  if (hypothesis.category === "idor") {
    const fallback2 = isLikelySpaFallback2(hypothesis.path, res);
    const confirmed = res.status >= 200 && res.status < 300 && body.trim().length > 0 && !fallback2;
    return {
      confirmed,
      reason: confirmed ? `IDOR probe returned HTTP ${res.status} with content \u2014 server may not enforce object-level ownership (A01:2025)` : fallback2 ? "response appears to be a generic SPA fallback document" : `probe returned HTTP ${res.status} \u2014 resource not accessible with mutated ID`
    };
  }
  if (hypothesis.category === "auth_bypass") {
    const confirmed = res.status >= 200 && res.status < 300;
    return {
      confirmed,
      reason: confirmed ? `unauthenticated request returned HTTP ${res.status} \u2014 endpoint may not enforce authentication` : `unauthenticated request was correctly rejected with HTTP ${res.status}`
    };
  }
  const fallback = isLikelySpaFallback2(hypothesis.path, res);
  const exposed = res.status >= 200 && res.status < 300 && body.trim().length > 0 && !fallback;
  return {
    confirmed: exposed,
    reason: exposed ? `path returned HTTP ${res.status} with body content` : fallback ? "path returned a generic SPA fallback document" : "path did not expose content"
  };
}
function findingFromProbe(h, probe2, nextId) {
  const lineStart = h.lineStart ?? 0;
  return {
    id: `A-${String(nextId).padStart(2, "0")}`,
    severity: h.severity,
    file: h.sourceFile ?? probe2.url,
    lineStart,
    lineEnd: lineStart,
    title: h.title,
    description: `${h.rationale}

Runtime evidence: ${String(probe2.evidence.reason ?? "probe confirmed")} at ${probe2.url}.`,
    remediation: h.remediation,
    reportedBy: [ATTACKER_NAME],
    confidence: 1
  };
}
function sanitizeHypotheses(hypotheses, targetUrl) {
  const origin = new URL(targetUrl).origin;
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const h of hypotheses) {
    try {
      const url = new URL(h.path, targetUrl);
      if (url.origin !== origin) continue;
      if (!["http:", "https:"].includes(url.protocol)) continue;
      if (!h.path.startsWith("/") && !h.path.startsWith(origin)) continue;
      const parameter = h.parameter?.trim();
      const parameterOptional = h.category === "path_exposure" || h.category === "idor" || h.category === "auth_bypass";
      if (!parameterOptional && !parameter) continue;
      if (parameter && !/^[A-Za-z0-9_.:-]{1,80}$/.test(parameter)) continue;
      if (h.category === "idor" && mutateIdorPath(h.path) === h.path) continue;
      const cleanPath = `${url.pathname}${url.search}`;
      const key = `${h.category}:${h.method}:${cleanPath}:${parameter ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ ...h, path: cleanPath, parameter });
    } catch {
    }
  }
  return out;
}
function parsePage(url, status, body, origin) {
  return {
    url,
    status,
    title: firstMatch(body, /<title[^>]*>([\s\S]*?)<\/title>/i),
    links: sameOriginLinks(url, body, origin),
    forms: parseForms(url, body, origin)
  };
}
function sameOriginLinks(baseUrl, body, origin) {
  const links = /* @__PURE__ */ new Set();
  for (const match of body.matchAll(/\bhref=["']([^"'#]+)["']/gi)) {
    try {
      const url = new URL(match[1] ?? "", baseUrl);
      if (url.origin === origin && (url.protocol === "http:" || url.protocol === "https:")) {
        url.hash = "";
        links.add(url.toString());
      }
    } catch {
    }
  }
  return [...links];
}
function parseForms(baseUrl, body, origin) {
  const forms = [];
  for (const match of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = match[1] ?? "";
    const formBody = match[2] ?? "";
    const action = attr(attrs, "action") ?? baseUrl;
    const method = (attr(attrs, "method") ?? "GET").toUpperCase() === "POST" ? "POST" : "GET";
    try {
      const url = new URL(action, baseUrl);
      if (url.origin !== origin) continue;
      const fields = [...formBody.matchAll(/\bname=["']([^"']+)["']/gi)].map((m) => m[1]).filter((name) => Boolean(name));
      forms.push({ action: url.toString(), method, fields });
    } catch {
    }
  }
  return forms;
}
function attr(attrs, name) {
  return firstMatch(attrs, new RegExp(`\\b${name}=["']([^"']+)["']`, "i"));
}
function firstMatch(text, re) {
  const value = re.exec(text)?.[1]?.trim();
  return value ? decodeHtml(value).slice(0, 200) : void 0;
}
function evaluateGates(findings, config) {
  const reasons = [];
  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const high = findings.filter((f) => f.severity === "HIGH").length;
  if (config.gates.block_on_confirmed_critical && critical > 0) {
    reasons.push(`${critical} confirmed CRITICAL AI attack finding${critical === 1 ? "" : "s"}`);
  }
  if (config.gates.block_on_confirmed_high && high > 0) {
    reasons.push(`${high} confirmed HIGH AI attack finding${high === 1 ? "" : "s"}`);
  }
  return { blocked: reasons.length > 0, reasons };
}
function remainingProbeSlots(budget) {
  return Math.max(0, budget.remaining());
}
function normalizeTargetUrl2(raw) {
  if (!raw) throw new Error("AI attack target URL required. Pass --target-url or set dynamic.target_url.");
  const url = new URL(raw);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`AI attack target must be http(s): ${raw}`);
  return url.toString();
}
function normalizeUrlForVisit(url) {
  const parsed = new URL(url);
  parsed.hash = "";
  return parsed.toString();
}
function defaultParameter(category) {
  if (category === "open_redirect") return "next";
  if (category === "error_disclosure") return "q";
  return "q";
}
async function safeText2(res) {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
function headersObject2(headers) {
  const out = {};
  headers.forEach((value, key) => {
    out[key] = key.toLowerCase() === "set-cookie" ? "<redacted>" : value;
  });
  return out;
}
function redactBody2(body) {
  return body.replace(/([A-Z0-9_]*TOKEN[A-Z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1<redacted>").replace(/([A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1<redacted>").replace(/([A-Z0-9_]*KEY[A-Z0-9_]*\s*=\s*)[^\s"'`]+/gi, "$1<redacted>");
}
function isLikelySpaFallback2(path, res) {
  const contentType = res.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("text/html")) return false;
  const body = res.bodySnippet.toLowerCase();
  if (!body.includes("<!doctype html") && !body.includes("<html")) return false;
  if (body.includes("/@vite/client") || body.includes("/@react-refresh")) return true;
  const suspiciousFilePath = /\.[a-z0-9]{2,8}$/i.test(path);
  if (suspiciousFilePath) return true;
  return body.includes('id="root"') || body.includes("id='root'") || body.includes('type="module"') || body.includes("type='module'");
}
function escapeHtml(s) {
  return s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function decodeHtml(s) {
  return s.replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", '"').replaceAll("&#39;", "'");
}
var RequestBudget = class {
  used = 0;
  lastRequestAt = 0;
  maxRequests;
  rateLimitPerSecond;
  constructor(maxRequests, rateLimitPerSecond) {
    this.maxRequests = Number.isFinite(maxRequests) && maxRequests >= 1 ? Math.floor(maxRequests) : 1;
    this.rateLimitPerSecond = Number.isFinite(rateLimitPerSecond) && rateLimitPerSecond > 0 ? rateLimitPerSecond : 0.1;
  }
  remaining() {
    return this.maxRequests - this.used;
  }
  async tryTake() {
    if (this.used >= this.maxRequests) return false;
    const minIntervalMs = Math.ceil(1e3 / this.rateLimitPerSecond);
    const waitMs = Math.max(0, this.lastRequestAt + minIntervalMs - Date.now());
    if (waitMs > 0) await new Promise((resolve2) => setTimeout(resolve2, waitMs));
    this.used += 1;
    this.lastRequestAt = Date.now();
    return true;
  }
};

// src/reporters/attack-markdown.ts
import { SEVERITY_ORDER } from "secure-review";
import { agreementCount } from "secure-review";

// src/internal/markdown-escape.ts
function escapeInlineCode(s) {
  if (s === void 0 || s === null) return "";
  return String(s).replace(/`/g, "\\`").replace(/\r?\n/g, " ");
}
function escapeTableCell(s, maxLen = 240) {
  if (s === void 0 || s === null) return "";
  return String(s).replace(/\|/g, "\\|").replace(/\r?\n/g, " ").slice(0, maxLen);
}
function escapeFencedBlock(s) {
  if (s === void 0 || s === null) return "";
  return String(s).replace(/```/g, "\\`\\`\\`").replace(
    /<\/(details|summary|script|style|iframe)/gi,
    (_m, tag) => `<\\/${tag}`
  );
}
function escapeBodyText(s) {
  if (s === void 0 || s === null) return "";
  return String(s).replace(/```/g, "\\`\\`\\`").replace(
    /<\/(details|summary|script|style|iframe)/gi,
    (_m, tag) => `<\\/${tag}`
  );
}
function escapeHeading(s, maxLen = 240) {
  return escapeBodyText(s).replace(/\r?\n/g, " ").slice(0, maxLen);
}

// src/reporters/attack-markdown.ts
function renderAttackReport(output) {
  const parts = [];
  parts.push(`# Secure Review \u2014 Runtime Attack Report`);
  parts.push(`
Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`);
  parts.push(`Target: ${escapeBodyText(output.targetUrl)}`);
  parts.push(`Duration: ${(output.totalDurationMs / 1e3).toFixed(1)}s`);
  parts.push(`Gate blocked: ${output.gateBlocked ? "YES" : "no"}`);
  if (output.gateReasons.length)
    parts.push(`Reasons: ${escapeBodyText(output.gateReasons.join("; "))}`);
  parts.push("");
  parts.push(`## Summary
`);
  parts.push(breakdownTable(output.breakdown));
  parts.push("");
  parts.push(`Total runtime findings: **${output.findings.length}**
`);
  parts.push(`## Checks
`);
  parts.push("| Check | URL | Status | OK | Duration | Error |");
  parts.push("|---|---|---:|---|---:|---|");
  for (const c of output.checks) {
    parts.push(
      `| ${escapeTableCell(c.check)} | \`${escapeInlineCode(c.url)}\` | ${escapeTableCell(c.status ?? "")} | ${c.ok ? "yes" : "no"} | ${(c.durationMs / 1e3).toFixed(1)}s | ${escapeTableCell(c.error ?? "")} |`
    );
  }
  parts.push("");
  parts.push(`## Runtime Findings
`);
  if (output.findings.length === 0) {
    parts.push("_No runtime findings._");
  } else {
    const sorted = sortByAgreement(output.findings);
    for (const f of sorted) parts.push(renderFinding(f));
  }
  return parts.join("\n");
}
function renderAttackAiReport(output) {
  const parts = [];
  parts.push(`# Secure Review \u2014 AI Attack Simulation Report`);
  parts.push(`
Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`);
  parts.push(`Target: ${escapeBodyText(output.targetUrl)}`);
  parts.push(
    `Attacker: **${escapeHeading(output.attacker.provider)}** / \`${escapeInlineCode(output.attacker.model)}\` \xB7 skill: \`${escapeInlineCode(output.attacker.skillPath)}\``
  );
  parts.push(`Duration: ${(output.totalDurationMs / 1e3).toFixed(1)}s`);
  parts.push(`Cost: $${output.totalCostUSD.toFixed(3)}`);
  parts.push(`Gate blocked: ${output.gateBlocked ? "YES" : "no"}`);
  if (output.gateReasons.length)
    parts.push(`Reasons: ${escapeBodyText(output.gateReasons.join("; "))}`);
  parts.push("");
  parts.push(`## Summary
`);
  parts.push(breakdownTable(output.breakdown));
  parts.push("");
  parts.push(`Crawled pages: **${output.pages.length}**`);
  parts.push(`Hypotheses planned: **${output.hypotheses.length}**`);
  parts.push(`Safe probes executed: **${output.probes.length}**`);
  parts.push(`Confirmed findings: **${output.findings.length}**
`);
  parts.push(`## Safety Limits
`);
  parts.push(`- Same-origin requests only`);
  parts.push(`- Max requests: ${output.limits.maxRequests}`);
  parts.push(`- Max crawl pages: ${output.limits.maxCrawlPages}`);
  parts.push(`- Rate limit: ${output.limits.rateLimitPerSecond}/second`);
  parts.push("");
  parts.push(`## Probes
`);
  parts.push("| Hypothesis | Category | Method | URL | Status | Confirmed | Error |");
  parts.push("|---|---|---|---|---:|---|---|");
  for (const p of output.probes) {
    parts.push(
      `| ${escapeTableCell(p.hypothesisId)} | ${escapeTableCell(p.category)} | ${escapeTableCell(p.method)} | \`${escapeInlineCode(p.url)}\` | ${escapeTableCell(p.status ?? "")} | ${p.confirmed ? "yes" : "no"} | ${escapeTableCell(p.error ?? "")} |`
    );
  }
  parts.push("");
  parts.push(`## Confirmed Findings
`);
  if (output.findings.length === 0) {
    parts.push("_No AI-planned probes produced confirmed runtime evidence._");
  } else {
    const sorted = sortByAgreement(output.findings);
    for (const f of sorted) parts.push(renderFinding(f));
  }
  return parts.join("\n");
}
function renderFinding(f) {
  const reporters = f.reportedBy.map(escapeHeading).join(", ");
  const tags = [f.cwe, f.owaspCategory].filter(Boolean).map(escapeHeading).join(" \xB7 ");
  const count = agreementCount(f);
  const agreementBadge = count > 1 ? ` \xB7 \u2705 confirmed by ${count} models` : "";
  const stableTag = f.stableId ? ` [${escapeHeading(f.stableId)}]` : "";
  return `
### ${escapeHeading(f.id)}${stableTag} \xB7 **${escapeHeading(f.severity)}** \xB7 ${escapeHeading(f.title)}${agreementBadge}

- **File:** \`${escapeInlineCode(`${f.file}:${f.lineStart}-${f.lineEnd}`)}\`
- **Tags:** ${tags || "\u2014"}
- **Reported by:** ${reporters}  (confidence: ${(f.confidence * 100).toFixed(0)}%, agreement: ${count} model${count !== 1 ? "s" : ""})

${escapeBodyText(f.description)}

${f.remediation ? `**Remediation:** ${escapeBodyText(f.remediation)}` : ""}
`;
}
function sortByAgreement(findings) {
  return [...findings].sort((a, b) => {
    const cntDiff = agreementCount(b) - agreementCount(a);
    if (cntDiff !== 0) return cntDiff;
    return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
  });
}
function breakdownTable(b) {
  const rows = ["| CRITICAL | HIGH | MEDIUM | LOW | INFO |", "|---:|---:|---:|---:|---:|"];
  rows.push(`| ${b.CRITICAL} | ${b.HIGH} | ${b.MEDIUM} | ${b.LOW} | ${b.INFO} |`);
  return rows.join("\n");
}

// src/reporters/attack-json.ts
function renderAttackEvidence(out, opts) {
  return {
    task_id: opts.taskId,
    tool: "secure-review",
    condition: "F-attack",
    run: opts.run,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
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
    generation_time_seconds: out.totalDurationMs / 1e3,
    total_cost_usd: 0,
    review_status: "ok",
    failed_reviewers: [],
    findings: out.findings,
    reviewers: opts.reviewerNames,
    iterations: 0,
    notes: out.gateBlocked ? `Gate blocked: ${out.gateReasons.join("; ")}` : void 0,
    target_url: out.targetUrl,
    checks: out.checks,
    runtime_findings: out.findings,
    gate_blocked: out.gateBlocked,
    gate_reasons: out.gateReasons
  };
}
function renderAttackAiEvidence(out, opts) {
  return {
    task_id: opts.taskId,
    tool: "secure-review",
    condition: "F-attack-ai",
    run: opts.run,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
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
    generation_time_seconds: out.totalDurationMs / 1e3,
    total_cost_usd: out.totalCostUSD,
    review_status: "ok",
    failed_reviewers: [],
    findings: out.findings,
    reviewers: opts.reviewerNames,
    iterations: 0,
    notes: out.gateBlocked ? `Gate blocked: ${out.gateReasons.join("; ")}` : void 0,
    target_url: out.targetUrl,
    crawled_pages: out.pages,
    hypotheses: out.hypotheses,
    probes: out.probes,
    runtime_findings: out.findings,
    gate_blocked: out.gateBlocked,
    gate_reasons: out.gateReasons,
    limits: out.limits
  };
}

// src/pentest/external-scanners.ts
import { spawnSync } from "child_process";
import { mkdtemp, readFile } from "fs/promises";
import { join } from "path";
import { tmpdir } from "os";

// src/internal/env-allowlist.ts
var BASE_ALLOWLIST_KEYS = /* @__PURE__ */ new Set([
  // POSIX identity and shell
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  // Locale and timezone
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  // Temp directories
  "TMPDIR",
  "TEMP",
  "TMP",
  // Safe Node tunable (NODE_OPTIONS / NODE_PATH / NODE_TLS_REJECT_UNAUTHORIZED
  // are intentionally NOT here — see file-level comment).
  "NODE_ENV",
  // Corporate proxy config (uppercase + lowercase forms)
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
  // Additive CA bundle for corporate MITM proxies (NOT a TLS bypass).
  "NODE_EXTRA_CA_CERTS"
]);
var BROWSER_AUTOMATION_KEYS = /* @__PURE__ */ new Set([
  "BROWSER",
  "CHROME_PATH",
  "CHROME_BIN",
  "CHROMIUM_FLAGS",
  "DISPLAY",
  "XAUTHORITY",
  "WAYLAND_DISPLAY",
  "XDG_CONFIG_HOME",
  "XDG_CACHE_HOME",
  "XDG_DATA_HOME",
  "XDG_RUNTIME_DIR"
]);
var BROWSER_AUTOMATION_PREFIXES = ["PLAYWRIGHT_", "PUPPETEER_"];
var SCANNER_KEYS = /* @__PURE__ */ new Set();
var SCANNER_PREFIXES = ["DOCKER_", "NUCLEI_"];
var FORWARD_PREFIX = "SECURE_REVIEW_FORWARD_";
function filterEnv(source, keys, prefixes) {
  const out = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === void 0) continue;
    if (keys.has(key) || prefixes.some((p) => key.startsWith(p))) {
      out[key] = value;
    }
  }
  for (const [key, value] of Object.entries(source)) {
    if (value === void 0) continue;
    if (!key.startsWith(FORWARD_PREFIX)) continue;
    const stripped = key.slice(FORWARD_PREFIX.length);
    if (!stripped) continue;
    out[stripped] = value;
  }
  return out;
}
function buildAllowlistedEnv(source = process.env) {
  const keys = /* @__PURE__ */ new Set([...BASE_ALLOWLIST_KEYS, ...BROWSER_AUTOMATION_KEYS]);
  return filterEnv(source, keys, BROWSER_AUTOMATION_PREFIXES);
}
function buildScannerEnv(source = process.env) {
  const keys = /* @__PURE__ */ new Set([...BASE_ALLOWLIST_KEYS, ...SCANNER_KEYS]);
  return filterEnv(source, keys, SCANNER_PREFIXES);
}

// src/pentest/external-scanners.ts
function mapNucleiSeverity(s) {
  const t = typeof s === "string" ? s.toLowerCase() : "";
  if (t === "critical") return "CRITICAL";
  if (t === "high") return "HIGH";
  if (t === "medium") return "MEDIUM";
  if (t === "low") return "LOW";
  return "INFO";
}
function findingFromNucleiLine(obj, index) {
  const info = typeof obj.info === "object" && obj.info !== null ? obj.info : {};
  const sev = mapNucleiSeverity(info.severity ?? obj.severity);
  const templateId = typeof obj["template-id"] === "string" ? obj["template-id"] : `nuclei-${index}`;
  const matchedAt = typeof obj["matched-at"] === "string" ? obj["matched-at"] : typeof obj.host === "string" ? obj.host : typeof obj.url === "string" ? obj.url : void 0;
  if (!matchedAt) return void 0;
  const title = typeof info.name === "string" ? `${templateId}: ${info.name}` : `nuclei: ${templateId}`;
  const desc = typeof info.description === "string" ? info.description : `Matched by nuclei template \`${templateId}\` during automated scan.`;
  return {
    id: `N-${String(index + 1).padStart(3, "0")}`,
    severity: sev,
    file: matchedAt,
    lineStart: 0,
    lineEnd: 0,
    title,
    description: desc,
    remediation: "Triage nuclei findings in context of your threat model (some template matches are benign). Patch confirmed issues.",
    reportedBy: ["nuclei"],
    confidence: 1
  };
}
function parseNucleiJsonExport(jsonl) {
  const findings = [];
  let i = 0;
  for (const row of jsonl.split(/\r?\n/)) {
    const line = row.trim();
    if (!line) continue;
    try {
      const obj = JSON.parse(line);
      const f = findingFromNucleiLine(obj, i++);
      if (f) findings.push(f);
    } catch {
    }
  }
  return findings;
}
function parseZapJunitBrief(xml, targetUrl) {
  const findings = [];
  const testcaseRe = /<testcase\b[^>]*\bname="([^"]*)"[^>]*>([\s\S]*?)<\/testcase>/gi;
  let m;
  let idx = 0;
  testcaseRe.lastIndex = 0;
  while ((m = testcaseRe.exec(xml)) !== null) {
    const name = m[1]?.trim() ?? `zap-issue-${idx + 1}`;
    const body = m[2] ?? "";
    if (!/<failure\b|<error\b/i.test(body)) continue;
    let severity = "MEDIUM";
    const low = `${name}${body}`.toLowerCase();
    if (/\bcritical\b/.test(low)) severity = "CRITICAL";
    else if (/\bhigh\b|\bsevere\b/.test(low)) severity = "HIGH";
    findings.push({
      id: `Z-${String(++idx).padStart(3, "0")}`,
      severity,
      file: targetUrl,
      lineStart: 0,
      lineEnd: 0,
      title: `ZAP baseline: ${name.slice(0, 280)}`,
      description: body.replace(/^[\s\S]*?<failure[^>]*>/i, "").replace(/<\/failure>[\s\S]*$/i, "").slice(0, 2e3) || `ZAP reported a baseline failure on ${targetUrl}`,
      remediation: "Review ZAP baseline output and mitigate or configure acceptable risk.",
      reportedBy: ["zap-baseline"],
      confidence: 1
    });
  }
  return findings;
}
async function runNucleiExport(targetUrl, timeoutMs) {
  const started = Date.now();
  const dir = await mkdtemp(join(tmpdir(), "sr-nuclei-"));
  const exportPath = join(dir, "results.json");
  try {
    const r = spawnSync(
      "nuclei",
      ["-silent", "-nc", "-u", targetUrl, "-json-export", exportPath],
      {
        encoding: "utf8",
        timeout: timeoutMs,
        maxBuffer: 20 * 1024 * 1024,
        env: buildScannerEnv()
      }
    );
    if (r.error?.code === "ENOENT") {
      return {
        scanner: "nuclei",
        ran: false,
        skippedReason: "`nuclei` binary not found on PATH",
        durationMs: Date.now() - started,
        markdownSection: "\n### Nuclei\n\n_Skipped: `nuclei` not installed._\n",
        findings: []
      };
    }
    let jsonl = "";
    try {
      jsonl = await readFile(exportPath, "utf8");
    } catch {
      jsonl = "";
    }
    const findings = parseNucleiJsonExport(jsonl);
    const status = typeof r.status === "number" ? r.status : -1;
    let md = `
### Nuclei (${findings.length} finding(s))

Exit code ${status}${r.stderr?.trim() ? ` \xB7 stderr excerpt: \`${escapeInlineCode(r.stderr.slice(0, 400))}\`` : ""}
`;
    md += `
| Severity | Title | Matched |
| --- | --- | --- |
`;
    for (const f of findings.slice(0, 50)) {
      md += `| ${f.severity} | ${escapeTableCell(f.title)} | \`${escapeInlineCode(f.file)}\` |
`;
    }
    if (findings.length > 50) md += `
_\u2026and ${findings.length - 50} more rows._
`;
    return {
      scanner: "nuclei",
      ran: true,
      exitCode: status,
      durationMs: Date.now() - started,
      markdownSection: md,
      findings
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      scanner: "nuclei",
      ran: false,
      skippedReason: msg,
      durationMs: Date.now() - started,
      markdownSection: `
### Nuclei

_Error: ${escapeTableCell(msg)}_
`,
      findings: []
    };
  }
}
async function runZapBaselineDocker(targetUrl, timeoutMs) {
  const started = Date.now();
  const dir = await mkdtemp(join(tmpdir(), "sr-zap-"));
  const xmlPath = join(dir, "report.xml");
  const args = [
    "run",
    "--rm",
    "-v",
    `${dir}:/zap/wrk:rw`,
    "ghcr.io/zaproxy/zaproxy:stable",
    "zap-baseline.py",
    "-t",
    targetUrl,
    "-J",
    "/zap/wrk/report.xml"
  ];
  const r = spawnSync("docker", args, {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 20 * 1024 * 1024,
    env: buildScannerEnv()
  });
  if (r.error?.code === "ENOENT") {
    return {
      scanner: "zap-baseline",
      ran: false,
      skippedReason: "`docker` not found",
      durationMs: Date.now() - started,
      markdownSection: "\n### ZAP baseline\n\n_Skipped: Docker unavailable._\n",
      findings: []
    };
  }
  let xml = "";
  try {
    xml = await readFile(xmlPath, "utf8");
  } catch {
    xml = "";
  }
  const findings = parseZapJunitBrief(xml, targetUrl);
  const exitCode = typeof r.status === "number" ? r.status : void 0;
  let md = `
### ZAP baseline (${findings.length} parsed failure row(s))

Docker exit ${exitCode ?? "unknown"}
`;
  md += failuresTable(findings.slice(0, 40));
  const stderrTail = r.stderr?.trim().slice(-1500);
  if (stderrTail)
    md += `
<details><summary>ZAP stderr excerpt</summary>

\`\`\`
${escapeFencedBlock(stderrTail)}
\`\`\`
</details>
`;
  return {
    scanner: "zap-baseline",
    ran: true,
    exitCode,
    durationMs: Date.now() - started,
    markdownSection: md,
    findings
  };
}
function failuresTable(findings) {
  if (findings.length === 0) return "\n_No JUnit failures parsed (clean or report missing)._";
  let t = `
| Severity | Title |
| --- | --- |
`;
  for (const f of findings) t += `| ${f.severity} | ${escapeTableCell(f.title)} |
`;
  return t;
}
function parsePentestScannerList(raw) {
  if (!raw?.trim()) return [];
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const p of raw.split(",")) {
    const s = p.trim().toLowerCase();
    let k;
    if (s === "zap-baseline" || s === "zap") k = "zap-baseline";
    else if (s === "nuclei") k = "nuclei";
    if (k && !seen.has(k)) {
      seen.add(k);
      out.push(k);
    }
  }
  return out;
}

// src/pentest/cli-scanners.ts
async function runCliPentestScanners(kinds, targetUrl, timeoutWallMs) {
  const findings = [];
  let appendixMarkdown = "";
  for (const k of kinds) {
    if (k === "zap-baseline") {
      const z2 = await runZapBaselineDocker(targetUrl, timeoutWallMs);
      appendixMarkdown += z2.markdownSection;
      findings.push(...z2.findings);
    } else {
      const n = await runNucleiExport(targetUrl, timeoutWallMs);
      appendixMarkdown += n.markdownSection;
      findings.push(...n.findings);
    }
  }
  return { appendixMarkdown, findings };
}

// src/pentest/gh-action-inputs.ts
function ghActionInput(name) {
  const normalized = name.replace(/-/g, "_").toUpperCase();
  const raw = process.env[`INPUT_${normalized}`];
  if (raw === void 0 || raw === "") return void 0;
  return raw.trim();
}

// src/pentest/browser-login.ts
import { execFileSync } from "child_process";
import { statSync } from "fs";
import { isAbsolute, resolve } from "path";
import { log as log4 } from "secure-review";
var DEFAULT_TIMEOUT_MS = 12e4;
function validateScriptPath(rawPath, cwd) {
  const trimmed = rawPath.trim();
  if (!trimmed) {
    throw new Error("Browser login script path is empty (after trim).");
  }
  const abs = isAbsolute(trimmed) ? trimmed : resolve(cwd, trimmed);
  let st;
  try {
    st = statSync(abs);
  } catch (err) {
    const code = err?.code;
    if (code === "ENOENT") {
      throw new Error(`Browser login script not found: ${abs}`);
    }
    if (code === "EACCES") {
      throw new Error(`Browser login script is not readable (EACCES): ${abs}`);
    }
    if (code === "ELOOP") {
      throw new Error(`Browser login script symlink loop: ${abs}`);
    }
    throw new Error(`Browser login script could not be stat'd (${code ?? "unknown"}): ${abs}`);
  }
  if (st.isDirectory()) {
    throw new Error(`Browser login script path is a directory, not a file: ${abs}`);
  }
  if (!st.isFile()) {
    throw new Error(
      `Browser login script path is not a regular file (got ${st.isSocket() ? "socket" : st.isFIFO() ? "fifo" : st.isBlockDevice() ? "block device" : st.isCharacterDevice() ? "char device" : "unknown type"}): ${abs}`
    );
  }
  return abs;
}
function runBrowserLoginScript(scriptPath, cwd, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const abs = validateScriptPath(scriptPath, cwd);
  const started = Date.now();
  try {
    const out = execFileSync(process.execPath, [abs], {
      cwd,
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 2 * 1024 * 1024,
      env: buildAllowlistedEnv()
    });
    const line = out.trim().split(/\r?\n/).filter(Boolean).at(-1)?.trim();
    if (!line) throw new Error("Browser login script produced no stdout");
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new Error("Browser login script must print JSON on the last stdout line");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error('Browser login JSON must be an object with a "headers" property');
    }
    const payload = parsed;
    if (!payload.headers || typeof payload.headers !== "object" || Array.isArray(payload.headers)) {
      throw new Error('Browser login JSON "headers" must be a plain object of name \u2192 string-value pairs');
    }
    const headers = {};
    const dropped = [];
    for (const [k, v] of Object.entries(payload.headers)) {
      if (typeof v === "string" && k.trim()) {
        headers[k] = v;
      } else {
        dropped.push(k.trim() ? k : "<empty key>");
      }
    }
    if (dropped.length > 0) {
      log4.warn(
        `browser-login script: ${dropped.length} header value${dropped.length === 1 ? "" : "s"} dropped because the value was not a string or the key was empty (${dropped.slice(0, 5).join(", ")}${dropped.length > 5 ? ", \u2026" : ""}). HTTP headers must be string-typed.`
      );
    }
    return { headers, stderr: "", durationMs: Date.now() - started };
  } catch (err) {
    const stderr = err instanceof Error ? err.message : String(err);
    throw new Error(`browser-login-script failed (${abs}): ${stderr}`);
  }
}

export {
  runAttackMode,
  crawlWithPlaywright,
  runAttackAiMode,
  mergeAttackerRef,
  renderAttackReport,
  renderAttackAiReport,
  renderAttackEvidence,
  renderAttackAiEvidence,
  parsePentestScannerList,
  runCliPentestScanners,
  ghActionInput,
  runBrowserLoginScript
};
//# sourceMappingURL=chunk-WKVCRHQI.js.map