/**
 * Defensive runtime guard against drift in the `secure-review` peer
 * dependency's config shape.
 *
 * `secure-review-runtime` directly accesses a small set of fields on the
 * loaded config (`dynamic.enabled`, `dynamic.target_url`,
 * `gates.max_cost_usd`). The peer's own Zod schema validates them at
 * load time today, so under a happy upgrade path nothing here triggers.
 *
 * The failure mode this guard catches: a published `secure-review@1.x.y`
 * removes or renames one of those fields. The user's pinned
 * `secure-review-runtime` was built against the old shape; at runtime
 * the property is `undefined`, and the runtime crashes later with an
 * unhelpful "cannot read property 'enabled' of undefined" or fires
 * unexpectedly because the gate read `undefined` instead of `false`.
 *
 * This guard converts that into a clear, single-message failure that
 * names the missing key and suggests pinning `secure-review` to the
 * tested-compatible range.
 */
export function assertRuntimeConfigShape(config: unknown): void {
  const errors: string[] = [];

  if (typeof config !== 'object' || config === null) {
    throw new Error(
      'secure-review schema drifted: loaded config is not an object. Pin `secure-review` to ^1.0.x in your devDependencies.',
    );
  }
  const c = config as Record<string, unknown>;

  if (typeof c.dynamic !== 'object' || c.dynamic === null) {
    errors.push('config.dynamic is missing or not an object');
  } else {
    const d = c.dynamic as Record<string, unknown>;
    if (typeof d.enabled !== 'boolean') {
      errors.push(
        'config.dynamic.enabled is missing or not a boolean (required for the runtime opt-in gate; without it the gate cannot decide whether to run)',
      );
    }
    if (d.target_url !== undefined && typeof d.target_url !== 'string') {
      errors.push(
        'config.dynamic.target_url is set but not a string (a URL is expected when present)',
      );
    }
  }

  if (c.gates !== undefined) {
    if (typeof c.gates !== 'object' || c.gates === null) {
      errors.push('config.gates is set but not an object');
    } else {
      const g = c.gates as Record<string, unknown>;
      if (g.max_cost_usd !== undefined && typeof g.max_cost_usd !== 'number') {
        errors.push(
          'config.gates.max_cost_usd is set but not a number (the attack-ai cost circuit breaker compares it against the planner cost as a number)',
        );
      }
    }
  }

  if (errors.length > 0) {
    throw new Error(
      'secure-review schema mismatch — secure-review-runtime cannot run against the loaded config:\n' +
        errors.map((e) => `  - ${e}`).join('\n') +
        '\n\nThis usually means the `secure-review` peer dependency was upgraded to a version with an incompatible config shape. ' +
        'Pin `secure-review` to a tested-compatible range (currently ^1.0.x) in your devDependencies, or upgrade `secure-review-runtime` to a version that supports the new shape.',
    );
  }
}
