/**
 * Opt-in gate for runtime attack modes (`attack` and `attack-ai`).
 *
 * Why this exists: the GitHub Action shipped by this package defaults
 * `mode: attack-ai` (see `action.yml`). Combined with a stale or
 * copy-pasted `dynamic.target_url` in `.secure-review.yml`, that means
 * every PR could silently fire LLM-planned probes (or deterministic HTTP
 * probes) at a third-party host the user no longer intends to test.
 *
 * Resolution: runtime attacks must be opted in to, either by setting
 * `dynamic.enabled: true` in the config or by passing the explicit
 * `--enable-runtime-attacks` CLI flag (or `INPUT_ENABLE_RUNTIME_ATTACKS`
 * Action input). Otherwise the runtime modes refuse to fire and emit a
 * clear warning explaining why.
 */

export interface RuntimeGateConfig {
  dynamic: { enabled?: boolean };
}

export type RuntimeGateDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

/**
 * Decide whether a runtime attack mode (attack / attack-ai) is allowed
 * to run.
 *
 * Order of precedence:
 *  1. Explicit CLI flag (`--enable-runtime-attacks`) → allowed.
 *  2. Explicit Action input (`INPUT_ENABLE_RUNTIME_ATTACKS=true`) →
 *     allowed (callers should map this to `enableFlag` before calling).
 *  3. Config `dynamic.enabled === true` → allowed.
 *  4. Default → blocked with an actionable message.
 */
export function isRuntimeAttackAllowed(
  config: RuntimeGateConfig,
  enableFlag: boolean | undefined,
): RuntimeGateDecision {
  if (enableFlag === true) return { allowed: true };
  if (config.dynamic.enabled === true) return { allowed: true };
  return {
    allowed: false,
    reason:
      'Runtime attacks are not enabled. Set `dynamic.enabled: true` in your config (.secure-review.yml) or pass `--enable-runtime-attacks` (CLI) / `enable-runtime-attacks: true` (GitHub Action input) to opt in. Skipping runtime probes; no requests sent.',
  };
}

/**
 * Parse a boolean from a string (used for the GH Action input mapping).
 * Accepts "true"/"1"/"yes"/"on" (case-insensitive) as true; anything
 * else (including unset / empty) as false. Mirrors GitHub Actions'
 * common boolean-input convention.
 */
export function parseBooleanFlag(raw: string | undefined): boolean {
  if (raw === undefined || raw === null) return false;
  const v = raw.trim().toLowerCase();
  return v === 'true' || v === '1' || v === 'yes' || v === 'on';
}
