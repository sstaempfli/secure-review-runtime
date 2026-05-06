/**
 * Markdown-output sanitisation helpers.
 *
 * Reporter output (`renderAttackReport`, `renderAttackAiReport`, the ZAP
 * stderr appendix) is posted verbatim as a GitHub PR comment. Finding
 * fields (`title`, `description`, `remediation`, `file`, `error`, …) come
 * from external sources — HTTP responses, AI-planned probe results, ZAP
 * stderr — and may legitimately contain Markdown-active characters:
 * pipes break tables, backticks break inline-code spans, triple backticks
 * break fenced blocks, and `</details>` tags close an enclosing
 * `<details>` block early.
 *
 * Each helper is intentionally narrow: pick the one that matches the
 * Markdown context you're interpolating into.
 */

/**
 * Escape for **inline-code spans**: protects against backtick-in-content
 * breaking the surrounding `\`${var}\`` delimiter pair. Also collapses
 * newlines (an inline-code span shouldn't contain them).
 */
export function escapeInlineCode(s: unknown): string {
  if (s === undefined || s === null) return '';
  return String(s).replace(/`/g, '\\`').replace(/\r?\n/g, ' ');
}

/**
 * Escape for **table cells**: replaces pipes and newlines (both break
 * GFM table parsing) and bounds the length so a runaway value doesn't
 * blow up the rendered comment width.
 */
export function escapeTableCell(s: unknown, maxLen = 240): string {
  if (s === undefined || s === null) return '';
  return String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').slice(0, maxLen);
}

/**
 * Escape for **fenced-block content**: any nested ``` inside a fenced
 * block ends the fence early. Replace each occurrence with an
 * escaped form that renders identically in GitHub Markdown
 * (`\`\`\``) but does not trigger fence-end parsing.
 *
 * Also escapes `</details>` / `</summary>` / `</script>` / `</style>` /
 * `</iframe>` so a fenced block embedded inside a `<details>` block
 * cannot close it early either.
 */
export function escapeFencedBlock(s: unknown): string {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/```/g, '\\`\\`\\`')
    .replace(
      /<\/(details|summary|script|style|iframe)/gi,
      (_m, tag: string) => `<\\/${tag}`,
    );
}

/**
 * Escape for **free-form body text** (headings, paragraphs).
 *
 * Neutralises triple backticks (which would open an unintended fenced
 * block mid-paragraph) and HTML close tags that could break out of a
 * surrounding GitHub-comment construct.
 */
export function escapeBodyText(s: unknown): string {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/```/g, '\\`\\`\\`')
    .replace(
      /<\/(details|summary|script|style|iframe)/gi,
      (_m, tag: string) => `<\\/${tag}`,
    );
}

/** Escape for **single-line body text** like a heading. Strips newlines. */
export function escapeHeading(s: unknown, maxLen = 240): string {
  return escapeBodyText(s).replace(/\r?\n/g, ' ').slice(0, maxLen);
}
