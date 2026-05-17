// Demo browser-login script for `--browser-login-script`.
//
// Contract (see the package README "Browser-login scripts run in a
// stripped environment"): print ONE line of JSON on the last stdout
// line, shaped `{ "headers": { "Cookie": "..." } }`. Those headers are
// merged into the crawl + probes, and any `Cookie` header is injected
// into the Playwright browser context so the crawler operates as a
// logged-in user.
//
// In a REAL target this script would drive Playwright: launch Chromium,
// navigate to the login page, fill + submit the form, then read the
// authenticated cookies back out, e.g.:
//
//   import { chromium } from 'playwright';
//   const b = await chromium.launch();
//   const p = await (await b.newContext()).newPage();
//   await p.goto(process.env.LOGIN_URL);
//   await p.fill('#email', process.env.LOGIN_USER);
//   await p.fill('#password', process.env.LOGIN_PASS);
//   await p.click('button[type=submit]');
//   const cookies = await p.context().cookies();
//   await b.close();
//   const cookie = cookies.map(c => `${c.name}=${c.value}`).join('; ');
//   console.log(JSON.stringify({ headers: { Cookie: cookie } }));
//
// The demo's vulnerable-target server has no real login form (it just
// honours any `session=` value that is not the weak default cookie), so
// this script emits a valid session deterministically and offline.

const session = process.env.SECURE_REVIEW_FORWARD_DEMO_SESSION || 'letmein';
console.log(JSON.stringify({ headers: { Cookie: `session=${session}` } }));
