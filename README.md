# secure-review-runtime

Companion package for **[secure-review](https://github.com/fonCki/secure-review)**. It owns **Layer 4** workflows: deterministic HTTP probes (`attack`), AI-planned same-origin probes (`attack-ai`), optional **OWASP ZAP** / **Nuclei** scanners, browser-login header hooks, and a **`pr-runtime`** GitHub Action entry for posting Markdown runtime findings.

Install alongside the static analyzer:

```bash
npm install --save-dev secure-review secure-review-runtime
```

CLI (global or `npx`):

```bash
npx secure-review-runtime attack . --target-url http://localhost:3000
npx secure-review-runtime attack-ai . --target-url http://localhost:3000
```

Use **`secure-review`** alone for `review`, `fix`, `scan`, and static PR comments; use this package when you need a **reachable base URL** and optional external scanners.

## Peer dependency

This package depends on **`secure-review` ≥ 1.x** (pinned in `package.json`). Shared types, adapters, config loading, and helpers come from the core library.

## License

MIT
