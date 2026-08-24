import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiCall, authorizeUrl, discover, exchangeCode, pkce, userinfo, verifyIdToken } from './oidc.js';

// The reZEN wordmark in its two official versions — black for light
// backgrounds, white for dark. Read once at startup so the pages never reach
// outside this process for an asset.
const assetDir = dirname(fileURLToPath(import.meta.url));
const LOGOS = {
  '/rezen-logo-black.svg': readFileSync(join(assetDir, 'rezen-logo-black.svg')),
  '/rezen-logo-white.svg': readFileSync(join(assetDir, 'rezen-logo-white.svg')),
};

// Sent on every response — defense in depth for a page that already escapes
// every dynamic value and renders nothing from a <script>.
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
};

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS });
  res.end(html);
}

function sendSvg(res, body) {
  res.writeHead(200, { 'Content-Type': 'image/svg+xml', ...SECURITY_HEADERS });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, ...SECURITY_HEADERS });
  res.end();
}

function requestUrl(req) {
  return new URL(req.url, `http://${req.headers.host || 'localhost'}`);
}

function escapeHtml(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const CSS = `
/* Login with reZEN — sample client.
 *
 * Two sheets on the reZEN brand palette: Chalk carrying Onyx type with Slate
 * for the quiet lines and Seaglass for every rule, and Cobalt carrying Chalk.
 * Headlines in the brand grotesk, body in its companion sans, and mono for
 * every value the flow returns. The accents stay small: Legacy Blue on focus
 * and progress, Aqua where the progress bar lands, Coral once or twice a page.
 * Self-contained by design — no webfonts, no icon sets, no external request
 * of any kind. The page renders offline.
 */

:root {
  /* brand palette */
  --chalk: #ffffff;
  --cobalt: #050e3d;
  --seaglass: #bfdddb;
  --slate: #615b56;
  --onyx: #1d1d1d;
  --coral: #ff557e;
  --legacy-blue: #05c3f9;
  --aqua: #00fbf0;

  --ink: var(--onyx);
  --muted: var(--slate);
  --rule: var(--seaglass);
  --ground: var(--chalk);

  --font-family-head: "Telegraf", "Poppins", "Inter", Arial, sans-serif;
  --font-family-body: "Inter", Arial, sans-serif;
  --font-family-mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
[hidden] { display: none !important; }

body {
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  font-family: var(--font-family-body);
  font-size: 16px;
  line-height: 1.6;
  background-color: var(--ground);
  /* a soft Seaglass wash off the top corner, and nothing else on the ground */
  background-image:
    radial-gradient(clamp(520px, 70vw, 900px) clamp(340px, 60vh, 620px) at 100% -12%, rgba(191, 221, 219, .34), rgba(191, 221, 219, 0) 62%);
  background-attachment: fixed;
}

/* ---- layout: one content column, offset left, wide margin to the right ---- */
.wrap {
  position: relative;
  z-index: 1;
  max-width: 1120px;
  margin: 0 auto;
  padding: clamp(44px, 9vh, 104px) 24px 80px;
}
.col {
  max-width: 620px;
  margin-left: clamp(0px, 5vw, 72px);
}
.wide { width: 100%; }
/* The landing is two panels and nothing else, so it centres itself on a tall
 * viewport. Browsers without :has() simply leave it top-aligned. */
.wrap:has(> .wide) {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

/* ---- type ---- */
/* The page mark keeps clear space of at least its own height on every side. */
.brandmark {
  display: block;
  height: 40px;
  width: auto;
  margin: 0 0 40px;
}
.brandmark.sm { height: 26px; margin-bottom: 30px; }

h1 {
  margin: 0 0 18px;
  font-family: var(--font-family-head);
  font-weight: 600;
  font-size: clamp(2.25rem, 6vw, 3.25rem);
  letter-spacing: -.03em;
  line-height: 1.02;
  text-wrap: balance;
}
h1.sm {
  font-size: clamp(1.8rem, 4.4vw, 2.35rem);
  margin-bottom: 28px;
}

.caption {
  margin: 18px 0 0;
  color: var(--muted);
  font-family: var(--font-family-mono);
  font-size: .78rem;
}
.error-text {
  margin: 0 0 28px;
  max-width: 46ch;
  color: var(--ink);
  font-size: 1.0625rem;
}

/* Section labels: a short Cobalt tick, mono small caps, a Seaglass rule to
 * the edge. */
.section-label {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 44px 0 16px;
  color: var(--muted);
  font-family: var(--font-family-mono);
  font-weight: 500;
  font-size: .69rem;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.section-label::before {
  content: "";
  width: 14px;
  height: 2px;
  background: var(--cobalt);
  flex: none;
}
.section-label::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--rule);
}

p { margin: 0 0 16px; }

a {
  color: var(--cobalt);
  font-weight: 500;
  text-decoration: underline;
  text-decoration-color: rgba(5, 14, 61, .3);
  text-decoration-thickness: 1px;
  text-underline-offset: 3px;
  transition: text-decoration-color .15s ease;
}
a:hover {
  text-decoration-color: var(--coral);
  text-decoration-thickness: 2px;
}
a:focus-visible {
  outline: 2px solid var(--legacy-blue);
  outline-offset: 3px;
  border-radius: 2px;
}
a.quiet {
  color: var(--muted);
  font-weight: 400;
  font-family: var(--font-family-mono);
  font-size: .78rem;
  text-decoration-color: var(--rule);
}
a.quiet:hover { color: var(--ink); text-decoration-color: var(--coral); }

/* ---- the two landing samples ---- */
.panels {
  display: grid;
  grid-template-columns: 1fr;
  gap: 20px;
}
@media (min-width: 880px) {
  .panels { grid-template-columns: 1fr 1fr; gap: 24px; }
}
.panel {
  position: relative;
  overflow: hidden;
  border-radius: 12px;
  padding: clamp(28px, 3.4vw, 44px);
}
.panel > * { position: relative; z-index: 1; }
/* A fine Seaglass drafting grid rises out of the top corner of each sheet and
 * fades before it reaches the copy. The same grid on both — it is the one
 * thing the two panels share besides the button. The mask only uses the
 * gradient's alpha, so it is drawn in Cobalt like everything else. */
.panel::before {
  content: "";
  position: absolute;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background-image:
    repeating-linear-gradient(0deg, var(--grid) 0 1px, transparent 1px 28px),
    repeating-linear-gradient(90deg, var(--grid) 0 1px, transparent 1px 28px);
  -webkit-mask-image: radial-gradient(560px 360px at 100% 0%, var(--cobalt) 0%, transparent 72%);
  mask-image: radial-gradient(560px 360px at 100% 0%, var(--cobalt) 0%, transparent 72%);
}
.panel-light {
  --grid: rgba(191, 221, 219, .75);
  background: var(--chalk);
  border: 1px solid var(--rule);
  color: var(--ink);
}
.panel-dark {
  --grid: rgba(191, 221, 219, .16);
  background-color: var(--cobalt);
  background-image: radial-gradient(520px 380px at 88% -14%, rgba(191, 221, 219, .22), rgba(191, 221, 219, 0) 62%);
  color: var(--chalk);
}
.panel-logo { display: block; height: 24px; width: auto; margin: 0 0 28px; }
.panel-kicker {
  margin: 0 0 10px;
  color: var(--muted);
  font-family: var(--font-family-mono);
  font-size: .68rem;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.panel h1,
.panel .display {
  margin: 0 0 14px;
  font-family: var(--font-family-head);
  font-weight: 600;
  font-size: clamp(1.9rem, 3.2vw, 2.5rem);
  letter-spacing: -.03em;
  line-height: 1.04;
  text-transform: none;
  text-wrap: balance;
  display: block;
  color: inherit;
}
.panel-copy {
  margin: 0 0 30px;
  max-width: 42ch;
  color: var(--muted);
  font-size: 1rem;
  text-wrap: pretty;
}
.panel-dark .panel-kicker,
.panel-dark .panel-copy,
.panel-dark .caption { color: var(--seaglass); }

/* ---- the button: reZEN's button language, scaled to a call to action ---- */
.cta { margin: 0; }

.rezen-btn {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  height: 52px;
  padding: 0 22px;
  border-radius: 8px;
  border: 2px solid var(--onyx);
  text-decoration: none;
  cursor: pointer;
  transition: transform .18s ease, box-shadow .18s ease, background-color .18s ease,
    border-color .18s ease, color .18s ease;
}
.rezen-btn-label {
  font-family: var(--font-family-body);
  font-size: 16px;
  font-weight: 600;
  line-height: 1;
  letter-spacing: -.005em;
  white-space: nowrap;
  transition: color .18s ease;
}
/* The wordmark is the word — the two assets are stacked and cross-faded so
 * the SVG itself is never recoloured. */
.rezen-btn-logo { position: relative; display: block; height: 26px; }
.rezen-btn-logo img { display: block; height: 26px; width: auto; transition: opacity .18s ease; }
.rezen-btn-logo img.swap { position: absolute; top: 0; left: 0; opacity: 0; }
.rezen-btn:hover .rezen-btn-logo img.rest { opacity: 0; }
.rezen-btn:hover .rezen-btn-logo img.swap { opacity: 1; }
.rezen-btn:focus-visible { outline: 2px solid var(--legacy-blue); outline-offset: 3px; }

/* on a light background: Chalk with an Onyx line, filling Cobalt on hover */
.rezen-btn.on-light { background: var(--chalk); color: var(--onyx); }
.rezen-btn.on-light .rezen-btn-label { color: var(--onyx); }
.rezen-btn.on-light:hover {
  background: var(--cobalt);
  border-color: var(--cobalt);
  transform: translateY(-1px);
  box-shadow: 0 8px 20px -6px rgba(5, 14, 61, .4);
}
.rezen-btn.on-light:hover .rezen-btn-label { color: var(--chalk); }

/* on Cobalt: open, with a Chalk line, filling Chalk on hover */
.rezen-btn.on-dark {
  background: transparent;
  border-color: var(--chalk);
  color: var(--chalk);
}
.rezen-btn.on-dark .rezen-btn-label { color: var(--chalk); }
.rezen-btn.on-dark:hover {
  background: var(--chalk);
  transform: translateY(-1px);
  box-shadow: 0 8px 22px -6px rgba(191, 221, 219, .45);
}
.rezen-btn.on-dark:hover .rezen-btn-label { color: var(--cobalt); }

.rezen-btn:active { transform: translateY(0); box-shadow: none; }
.rezen-btn:disabled { opacity: .45; cursor: default; }
.rezen-btn:disabled:hover { transform: none; box-shadow: none; }
.rezen-btn:disabled:hover .rezen-btn-logo img.rest { opacity: 1; }
.rezen-btn:disabled:hover .rezen-btn-logo img.swap { opacity: 0; }
.rezen-btn.on-light:disabled:hover { background: var(--chalk); border-color: var(--onyx); }
.rezen-btn.on-light:disabled:hover .rezen-btn-label { color: var(--onyx); }
.rezen-btn.on-dark:disabled:hover { background: transparent; }
.rezen-btn.on-dark:disabled:hover .rezen-btn-label { color: var(--chalk); }

/* ---- values the flow returns: always mono ---- */
table.kv {
  border-collapse: collapse;
  width: 100%;
  font-family: var(--font-family-mono);
  font-size: .82rem;
}
table.kv td {
  padding: 11px 0;
  border-bottom: 1px solid var(--rule);
  vertical-align: top;
}
table.kv tr:last-child td { border-bottom: 0; }
table.kv td:first-child {
  width: 34%;
  padding-right: 16px;
  color: var(--muted);
}
table.kv td:last-child { word-break: break-word; }

.card {
  background: var(--chalk);
  border: 1px solid var(--rule);
  border-radius: 8px;
  padding: 4px 18px;
}

/* Identity scopes sit Onyx on Chalk; data scopes on the Real API sit Cobalt
 * on Seaglass. */
ul.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.chip {
  padding: 5px 12px;
  border: 1px solid var(--rule);
  border-radius: 999px;
  background: var(--chalk);
  color: var(--ink);
  font-family: var(--font-family-mono);
  font-size: .74rem;
  letter-spacing: .02em;
  white-space: nowrap;
}
.chip.data {
  color: var(--cobalt);
  border-color: var(--seaglass);
  background: var(--seaglass);
}

/* ---- what happened: a timeline, one Cobalt tick per step ---- */
ol.steps {
  list-style: none;
  margin: 0;
  padding: 2px 0 2px 26px;
  border-left: 1px solid var(--rule);
}
ol.steps li {
  position: relative;
  margin: 0 0 14px;
  color: var(--ink);
  font-family: var(--font-family-mono);
  font-size: .78rem;
  line-height: 1.55;
}
ol.steps li:last-child { margin-bottom: 0; }
ol.steps li::before {
  content: "✓";
  position: absolute;
  left: -35px;
  top: 0;
  width: 18px;
  height: 18px;
  display: grid;
  place-items: center;
  border: 1px solid var(--rule);
  border-radius: 50%;
  background: var(--chalk);
  color: var(--cobalt);
  font-size: .62rem;
  font-weight: 700;
  line-height: 1;
}
ol.steps li.warn::before {
  content: "!";
  color: var(--coral);
  border-color: var(--coral);
}

.logout { margin: 44px 0 0; }

/* ---- failure: one short Coral rule above the headline ---- */
.error-rule {
  display: block;
  width: 36px;
  height: 3px;
  margin: 0 0 22px;
  border-radius: 999px;
  background: var(--coral);
}

/* ---- one orchestrated reveal on load, and nothing else moving ---- */
@keyframes rise {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: none; }
}
.reveal > *,
.panel.reveal > * { animation: rise .5s cubic-bezier(.22, .68, .28, 1) both; }
.reveal > :nth-child(1) { animation-delay: 0ms; }
.reveal > :nth-child(2) { animation-delay: 90ms; }
.reveal > :nth-child(3) { animation-delay: 180ms; }
.reveal > :nth-child(4) { animation-delay: 270ms; }
.reveal > :nth-child(5) { animation-delay: 360ms; }
.reveal > :nth-child(6) { animation-delay: 450ms; }
.reveal > :nth-child(n + 7) { animation-delay: 540ms; }

@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: .001ms !important;
    animation-delay: 0ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .001ms !important;
  }
}
`;

function layout(title, body, wrapperClass = 'col reveal') {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/rezen-logo-black.svg">
<title>${escapeHtml(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="wrap"><div class="${wrapperClass}">${body}</div></div>
</body>
</html>`;
}

function errorPage(message) {
  return layout('Sign-in failed', `
    <img class="brandmark sm" src="/rezen-logo-black.svg" alt="reZEN">
    <span class="error-rule" aria-hidden="true"></span>
    <h1 class="sm">Sign-in failed</h1>
    <p class="error-text">${escapeHtml(message)}</p>
    <p><a href="/">Start again</a></p>
  `);
}

// The scopes that release identity claims are shown Onyx on Chalk; everything
// else is a data scope on the Real API, shown Cobalt on Seaglass.
const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email', 'real.identity']);

function scopeChips(scope) {
  const granted = String(scope || '').split(/\s+/).filter(Boolean);
  if (!granted.length) return '<p class="caption">No scope was granted.</p>';
  return `<ul class="chips">${granted
    .map((s) => `<li class="chip${IDENTITY_SCOPES.has(s) ? '' : ' data'}">${escapeHtml(s)}</li>`)
    .join('')}</ul>`;
}

// The button is "Login with" followed by the wordmark itself — the logo is
// the word. Each variant carries both assets and cross-fades to the other on
// hover, as the fill inverts: black to white on a light background, white to
// black on a dark one.
function loginButton(variant) {
  const [rest, swap] = variant === 'on-dark' ? ['white', 'black'] : ['black', 'white'];
  const logo = `<img class="rest" src="/rezen-logo-${rest}.svg" alt="reZEN">`
    + `<img class="swap" src="/rezen-logo-${swap}.svg" alt="" aria-hidden="true">`;
  return `<a class="rezen-btn ${variant}" href="/login" aria-label="Login with reZEN">`
    + '<span class="rezen-btn-label">Login with</span>'
    + `<span class="rezen-btn-logo">${logo}</span></a>`;
}

function homePage(sessionData) {
  if (sessionData?.identity) {
    const { sub, name, email, yentaId } = sessionData.identity;
    const identityRows = [
      ['sub', sub],
      ['name', name ?? '(not present)'],
      ['email', email ?? '(not present)'],
      ['yentaId', yentaId ?? '(not present)'],
    ];
    const identityTable = `<table class="kv">${identityRows
      .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`)
      .join('')}</table>`;
    const profileBlock = sessionData.profile
      ? `<h2 class="section-label">Profile</h2><div class="card"><table class="kv">`
        + `<tr><td>displayName</td><td>${escapeHtml(String(sessionData.profile.displayName))}</td></tr>`
        + `<tr><td>type</td><td>${escapeHtml(String(sessionData.profile.type))}</td></tr>`
        + `</table></div>`
      : `<h2 class="section-label">Profile</h2><p class="caption">The /me call did not return a result — see the steps below.</p>`;
    // A step that reports a failure gets a different marker — the timeline is
    // a record of what happened, not a row of ticks.
    const steps = (sessionData.steps || [])
      .map((s) => `<li${/failed/i.test(s) ? ' class="warn"' : ''}>${escapeHtml(s)}</li>`)
      .join('');
    return layout('Signed in with reZEN', `
      <img class="brandmark sm" src="/rezen-logo-black.svg" alt="reZEN">
      <h1 class="sm">Signed in with reZEN</h1>
      <h2 class="section-label">Identity</h2>
      ${identityTable}
      <h2 class="section-label">Granted scope</h2>
      ${scopeChips(sessionData.scope)}
      ${profileBlock}
      <h2 class="section-label">What happened</h2>
      <ol class="steps">${steps}</ol>
      <p class="logout"><a class="quiet" href="/logout">Log out</a></p>
    `);
  }
  return layout('Login with reZEN', `
    <div class="panels">
      <div class="panel panel-light reveal">
        <img class="panel-logo" src="/rezen-logo-black.svg" alt="reZEN">
        <p class="panel-kicker">On a light background</p>
        <h1>Login with reZEN</h1>
        <p class="panel-copy">This sample runs the authorization code flow with PKCE against a
        reZEN OIDC issuer, verifies your identity, and calls one Real API on your behalf.</p>
        <p class="cta">${loginButton('on-light')}</p>
        <p class="caption">Sign in with your reZEN account to continue</p>
      </div>
      <div class="panel panel-dark reveal">
        <img class="panel-logo" src="/rezen-logo-white.svg" alt="reZEN">
        <p class="panel-kicker">On a dark background</p>
        <h2 class="display">Login with reZEN</h2>
        <p class="panel-copy">The same flow, the same client, the same button — drawn for a dark
        page. Either button starts the sign-in.</p>
        <p class="cta">${loginButton('on-dark')}</p>
        <p class="caption">Sign in with your reZEN account to continue</p>
      </div>
    </div>
  `, 'wide');
}

function mapAuthorizeError(err, description) {
  const known = {
    access_denied: 'You declined the consent screen — sign in again if that was not intended.',
    invalid_scope: 'One or more requested scopes are not allowed for this client.',
    unauthorized_client: 'This client is not authorized for this grant.',
  };
  return known[err] || `Authorization failed: ${err}${description ? ` — ${description}` : ''}`;
}

function mapTokenError(err) {
  const known = {
    invalid_grant: 'The authorization code expired (60 seconds), was already used, or the code verifier did not match — start again.',
    invalid_client: 'The client secret is wrong.',
  };
  return known[err] || `Token exchange failed${err ? `: ${err}` : ''}.`;
}

// Sessions older than this are swept on every /login; the map itself is
// capped so an endless stream of uncookied /login calls can't grow it
// without bound — both are sample-scale limits, not a real eviction policy.
const SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000;
const SESSION_CAP = 1000;

export function createServer(config) {
  // One in-memory session per signed-in visitor, keyed by an httpOnly cookie.
  // Tokens live only in this map, in this process — never on disk, never in a
  // log line, never rendered.
  const sessions = new Map();
  // Discovery is read once and reused; a failed read is not cached.
  let discoveryPromise;
  const getDiscovery = () => (discoveryPromise ??= discover(config.issuer).catch((err) => {
    discoveryPromise = undefined;
    throw err;
  }));

  function getSession(req) {
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.match(/(?:^|;\s*)sid=([^;]+)/);
    const id = match?.[1];
    return id && sessions.has(id) ? { id, data: sessions.get(id) } : undefined;
  }

  // Drops sessions older than SESSION_MAX_AGE_MS, then evicts the oldest
  // survivors (the Map iterates in insertion order, which is creation order
  // here — a session id is never reused) until the map is back at the cap.
  function sweepSessions() {
    const cutoff = Date.now() - SESSION_MAX_AGE_MS;
    for (const [id, data] of sessions) {
      if ((data.createdAt ?? 0) < cutoff) sessions.delete(id);
    }
    while (sessions.size > SESSION_CAP) {
      sessions.delete(sessions.keys().next().value);
    }
  }

  // Always mints a fresh session id — /login is where sign-in starts, and a
  // pre-existing sid (uncookied visitor, or a stale session) must not be
  // carried into the newly authenticated session.
  function newSession(req, res) {
    const existing = getSession(req);
    if (existing) sessions.delete(existing.id);
    sweepSessions();
    const id = randomBytes(24).toString('base64url');
    const data = { createdAt: Date.now() };
    sessions.set(id, data);
    // Add Secure when serving over HTTPS; omitted so the loopback http://[::1] sample works.
    res.setHeader('Set-Cookie', `sid=${id}; HttpOnly; Path=/; SameSite=Lax`);
    return { id, data };
  }

  const handler = async (req, res) => {
    const url = requestUrl(req);
    try {
      if (req.method === 'GET' && url.pathname === '/') {
        const session = getSession(req);
        return sendHtml(res, homePage(session?.data));
      }

      if (req.method === 'GET' && LOGOS[url.pathname]) {
        return sendSvg(res, LOGOS[url.pathname]);
      }

      if (req.method === 'GET' && url.pathname === '/login') {
        const session = newSession(req, res);
        let discovery;
        try {
          discovery = await getDiscovery();
        } catch (err) {
          return sendHtml(res, errorPage(`Could not read the discovery document: ${err.message}`), 400);
        }
        const { verifier, challenge } = pkce();
        const state = randomBytes(16).toString('base64url');
        const nonce = randomBytes(16).toString('base64url');
        session.data.flow = { verifier, state, nonce };
        const target = authorizeUrl(discovery, {
          clientId: config.clientId,
          redirectUri: config.redirectUri,
          scopes: config.scopes,
          state,
          nonce,
          challenge,
        });
        return redirect(res, target);
      }

      if (req.method === 'GET' && url.pathname === '/callback') {
        const session = getSession(req);
        if (!session) return sendHtml(res, errorPage('No active sign-in session — start again.'), 400);

        const errParam = url.searchParams.get('error');
        if (errParam) {
          return sendHtml(
            res,
            errorPage(mapAuthorizeError(errParam, url.searchParams.get('error_description'))),
            400,
          );
        }

        const flow = session.data.flow;
        if (!flow || url.searchParams.get('state') !== flow.state) {
          return sendHtml(res, errorPage('The state parameter did not match — start again.'), 400);
        }
        if (url.searchParams.get('iss') !== config.issuer) {
          return sendHtml(res, errorPage('The issuer on the callback did not match — start again.'), 400);
        }

        let discovery;
        try {
          discovery = await getDiscovery();
        } catch (err) {
          return sendHtml(res, errorPage(`Could not read the discovery document: ${err.message}`), 400);
        }

        const tokenRes = await exchangeCode(discovery, {
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          code: url.searchParams.get('code'),
          redirectUri: config.redirectUri,
          verifier: flow.verifier,
        });
        if (tokenRes.status !== 200) {
          return sendHtml(res, errorPage(mapTokenError(tokenRes.body?.error)), 400);
        }

        let jwks;
        try {
          const jwksRes = await fetch(discovery.jwks_uri);
          if (!jwksRes.ok) {
            return sendHtml(res, errorPage(`Could not fetch the signing keys (HTTP ${jwksRes.status})`), 400);
          }
          jwks = await jwksRes.json();
        } catch (err) {
          return sendHtml(res, errorPage(`Could not fetch the signing keys: ${err.message}`), 400);
        }

        let claims;
        try {
          claims = await verifyIdToken(tokenRes.body.id_token, {
            jwks,
            issuer: config.issuer,
            clientId: config.clientId,
            nonce: flow.nonce,
          });
        } catch (err) {
          return sendHtml(res, errorPage(`Sign-in could not be verified: ${err.message}`), 400);
        }

        const accessToken = tokenRes.body.access_token;
        const steps = ['Code exchanged for tokens', 'ID token verified (RS256, nonce checked)'];

        // Identity comes from /userinfo — the id_token proves who signed in
        // (sub), /userinfo carries the claims the granted scopes release.
        // OIDC Core 5.3.2: only trust /userinfo when its sub matches the
        // verified id_token — otherwise keep the id_token's claims as-is.
        let identity = claims;
        try {
          const userinfoRes = await userinfo(discovery, accessToken);
          if (userinfoRes.status !== 200) {
            steps.push(`Userinfo call failed (HTTP ${userinfoRes.status})`);
          } else if (typeof userinfoRes.body === 'object' && userinfoRes.body.sub === claims.sub) {
            identity = { ...claims, ...userinfoRes.body };
            steps.push('Userinfo fetched');
          } else {
            steps.push('Userinfo ignored — sub did not match the ID token');
          }
        } catch (err) {
          steps.push(`Userinfo call failed (${err.message})`);
        }

        let profile;
        try {
          const profileRes = await apiCall(config.apiBase, '/api/v1/users/me', accessToken);
          if (profileRes.status === 200) {
            profile = {
              displayName: profileRes.body.displayName ?? '(not present)',
              type: profileRes.body.type ?? '(not present)',
            };
            steps.push('Profile fetched from /me with x-api-key (200)');
          } else {
            steps.push(`Profile call failed (HTTP ${profileRes.status})`);
          }
        } catch (err) {
          steps.push(`Profile call failed (${err.message})`);
        }

        // RFC 6749 §5.1: scope is OPTIONAL in the token response when it
        // equals the request — a compliant server may omit it entirely.
        session.data.identity = { sub: identity.sub, name: identity.name, email: identity.email, yentaId: identity.yentaId };
        session.data.scope = tokenRes.body.scope || config.scopes.join(' ');
        session.data.profile = profile;
        session.data.steps = steps;
        session.data.flow = undefined;

        return redirect(res, '/');
      }

      if (req.method === 'GET' && url.pathname === '/logout') {
        const session = getSession(req);
        if (session) sessions.delete(session.id);
        res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
        return redirect(res, '/');
      }

      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
      res.end('not found');
    } catch (err) {
      console.error('unexpected error:', err?.message || err);
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
      res.end('unexpected error');
    }
  };

  return http.createServer(handler);
}
