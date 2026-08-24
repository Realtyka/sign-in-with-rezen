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

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendSvg(res, body) {
  res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
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
 * Editorial minimalism on the reZEN brand tokens (ink #1d1d1d, blue #4967fd,
 * paper #fbfbfa): a paper ground with a soft blue wash and a barely-there
 * grain, a serif display face paired with mono for every value the flow
 * returns, and one accent colour. Self-contained by design — no webfonts, no
 * icon sets, no external request of any kind. The page renders offline.
 */

:root {
  --ink: #1d1d1d;
  --muted: #52525b;
  --blue: #4967fd;
  --paper: #fbfbfa;
  --hairline: #e4e4e7;
  --card: #ffffff;
  /* reZEN button tokens */
  --btn-ink: #282826;
  --btn-ink-border: #3e3f3c;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
  --serif: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  --sans: -apple-system, "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
[hidden] { display: none !important; }

body {
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  font-family: var(--serif);
  font-size: 17px;
  line-height: 1.6;
  background-color: var(--paper);
  background-image:
    radial-gradient(820px 620px at 92% -10%, rgba(73, 103, 253, .16), rgba(73, 103, 253, 0) 60%),
    radial-gradient(680px 520px at -12% 110%, rgba(73, 103, 253, .08), rgba(73, 103, 253, 0) 58%);
  background-attachment: fixed;
}

/* Two inert layers behind the content: a fine grain, and the wordmark
 * ghosted into the bottom-right corner and cropped by the viewport. Both
 * are drawn from local sources — the grain is an inline SVG data URI. */
body::before {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  opacity: .22;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='180' height='180' filter='url(%23g)' opacity='0.55'/%3E%3C/svg%3E");
}
body::after {
  content: "";
  position: fixed;
  right: -6vw;
  bottom: -5vh;
  width: 34vw;
  max-width: 400px;
  aspect-ratio: 361 / 133;
  z-index: 0;
  pointer-events: none;
  opacity: .045;
  background: url("/rezen-logo-black.svg") no-repeat right center / 180% auto;
}
@media (max-width: 760px) {
  body::after { display: none; }
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
.brandmark {
  display: block;
  height: 40px;
  width: auto;
  margin: 0 0 30px;
}
.brandmark.sm { height: 26px; margin-bottom: 22px; }

h1 {
  margin: 0 0 18px;
  font-family: var(--serif);
  font-weight: 400;
  font-size: clamp(2.35rem, 6.4vw, 3.35rem);
  letter-spacing: -.028em;
  line-height: 1.03;
}
h1.sm {
  font-size: clamp(1.85rem, 4.6vw, 2.45rem);
  margin-bottom: 28px;
}

.caption {
  margin: 18px 0 0;
  color: var(--muted);
  font-family: var(--mono);
  font-size: .78rem;
}
.error-text {
  margin: 0 0 28px;
  max-width: 46ch;
  color: var(--ink);
  font-size: 1.0625rem;
}
.status {
  margin: 12px 0 0;
  min-height: 1.2em;
  color: var(--blue);
  font-family: var(--mono);
  font-size: .78rem;
}

/* Section labels: a short blue tick, mono small caps, a hairline to the edge. */
.section-label {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 44px 0 16px;
  color: var(--muted);
  font-family: var(--mono);
  font-weight: 500;
  font-size: .69rem;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.section-label::before {
  content: "";
  width: 14px;
  height: 2px;
  background: var(--blue);
  flex: none;
}
.section-label::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--hairline);
}

p { margin: 0 0 16px; }

a {
  color: var(--blue);
  text-decoration: none;
  border-bottom: 1px solid rgba(73, 103, 253, .3);
}
a:hover { border-bottom-color: var(--blue); }
a:focus-visible {
  outline: 2px solid var(--blue);
  outline-offset: 3px;
  border-radius: 2px;
}
a.quiet {
  color: var(--muted);
  border-bottom-color: var(--hairline);
  font-family: var(--mono);
  font-size: .78rem;
}
a.quiet:hover { color: var(--ink); border-bottom-color: var(--muted); }

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
  border-radius: 14px;
  padding: clamp(28px, 3.4vw, 44px);
}
.panel > * { position: relative; z-index: 1; }
.panel-light {
  background: transparent;
  border: 1px solid var(--hairline);
}
.panel-dark {
  border: 1px solid var(--btn-ink-border);
  background-color: var(--ink);
  background-image: radial-gradient(520px 380px at 88% -14%, rgba(73, 103, 253, .3), rgba(73, 103, 253, 0) 62%);
  color: #fff;
}
/* the same grain as the paper ground, over the dark panel */
.panel-dark::before {
  content: "";
  position: absolute;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  opacity: .3;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='180' height='180' filter='url(%23g)' opacity='0.55'/%3E%3C/svg%3E");
}
.panel-logo { display: block; height: 24px; width: auto; margin: 0 0 20px; }
.panel-kicker {
  margin: 0 0 10px;
  color: var(--muted);
  font-family: var(--mono);
  font-size: .68rem;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.panel h1,
.panel .display {
  margin: 0 0 14px;
  font-family: var(--serif);
  font-weight: 400;
  font-size: clamp(2rem, 3.4vw, 2.6rem);
  letter-spacing: -.028em;
  line-height: 1.05;
  text-transform: none;
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
.panel-dark .panel-kicker { color: rgba(255, 255, 255, .5); }
.panel-dark .panel-copy { color: rgba(255, 255, 255, .62); }
.panel-dark .caption { color: rgba(255, 255, 255, .5); }

/* ---- the button: reZEN's button language, scaled to a call to action ---- */
.cta { margin: 0; }

.rezen-btn {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  height: 52px;
  padding: 0 22px;
  border-radius: 8px;
  border: 2px solid var(--btn-ink);
  text-decoration: none;
  cursor: pointer;
  transition: transform .18s ease, box-shadow .18s ease, background-color .18s ease,
    border-color .18s ease, color .18s ease;
}
.rezen-btn-label {
  font-family: var(--sans);
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
.rezen-btn:focus-visible { outline: 2px solid var(--blue); outline-offset: 3px; }

/* on a light background: outlined, inverting on hover */
.rezen-btn.on-light { background: #fff; color: var(--btn-ink); }
.rezen-btn.on-light .rezen-btn-label { color: var(--btn-ink); }
.rezen-btn.on-light:hover {
  background: var(--btn-ink);
  transform: translateY(-1px);
  box-shadow: 0 8px 20px -6px rgba(40, 40, 38, .38);
}
.rezen-btn.on-light:hover .rezen-btn-label { color: #fff; }
.rezen-btn.on-light:hover .rezen-btn-logo img.rest { opacity: 0; }
.rezen-btn.on-light:hover .rezen-btn-logo img.swap { opacity: 1; }

/* on a dark background: dark fill, the border coming up to white */
.rezen-btn.on-dark {
  background: var(--btn-ink);
  border-color: var(--btn-ink-border);
  color: #fff;
}
.rezen-btn.on-dark .rezen-btn-label { color: #fff; }
.rezen-btn.on-dark:hover {
  border-color: #fff;
  transform: translateY(-1px);
  box-shadow: 0 8px 22px -6px rgba(73, 103, 253, .55);
}

.rezen-btn:active { transform: translateY(0); box-shadow: none; }
.rezen-btn:disabled { opacity: .45; cursor: default; }
.rezen-btn:disabled:hover {
  transform: none;
  box-shadow: none;
  background: #fff;
  border-color: var(--btn-ink);
}
.rezen-btn.on-dark:disabled:hover { background: var(--btn-ink); border-color: var(--btn-ink-border); }
.rezen-btn.on-light:disabled:hover .rezen-btn-label { color: var(--btn-ink); }
.rezen-btn.on-light:disabled:hover .rezen-btn-logo img.rest { opacity: 1; }
.rezen-btn.on-light:disabled:hover .rezen-btn-logo img.swap { opacity: 0; }

/* ---- values the flow returns: always mono ---- */
table.kv {
  border-collapse: collapse;
  width: 100%;
  font-family: var(--mono);
  font-size: .82rem;
}
table.kv td {
  padding: 11px 0;
  border-bottom: 1px solid var(--hairline);
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
  background: var(--card);
  border: 1px solid var(--hairline);
  border-radius: 8px;
  padding: 4px 18px;
}

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
  border: 1px solid var(--hairline);
  border-radius: 999px;
  background: var(--card);
  color: var(--ink);
  font-family: var(--mono);
  font-size: .74rem;
  letter-spacing: .02em;
  white-space: nowrap;
}
.chip.data {
  color: var(--blue);
  border-color: rgba(73, 103, 253, .35);
  background: rgba(73, 103, 253, .05);
}

/* ---- what happened: a timeline, one tick per step ---- */
ol.steps {
  list-style: none;
  margin: 0;
  padding: 2px 0 2px 26px;
  border-left: 1px solid var(--hairline);
}
ol.steps li {
  position: relative;
  margin: 0 0 14px;
  color: var(--ink);
  font-family: var(--mono);
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
  border: 1px solid var(--hairline);
  border-radius: 50%;
  background: var(--paper);
  color: var(--blue);
  font-size: .62rem;
  line-height: 1;
}
ol.steps li.warn::before {
  content: "!";
  color: var(--muted);
}

.logout { margin: 44px 0 0; }

/* ---- the popup: 520x720, so the column centres and the ghost stays out ---- */
.signing .wrap {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 32px 34px 44px;
}
.signing .col { margin-left: 0; }
.signing h1 { font-size: clamp(1.9rem, 6vw, 2.35rem); }
.signing .message { margin: 0; color: var(--muted); font-family: var(--mono); font-size: .8rem; }
.signing .restart { display: none; margin: 24px 0 0; }
.signing.is-error .message { color: var(--ink); }
.signing.is-error .progress { display: none; }
.signing.is-error .restart { display: block; }

.progress {
  position: relative;
  overflow: hidden;
  width: 220px;
  max-width: 100%;
  height: 3px;
  margin: 28px 0 0;
  border-radius: 999px;
  background: var(--hairline);
}
.progress::after {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  left: 0;
  width: 38%;
  border-radius: 999px;
  background: var(--blue);
  animation: slide 1.25s ease-in-out infinite;
}
@keyframes slide {
  from { transform: translateX(-110%); }
  to { transform: translateX(360%); }
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
    <h1 class="sm">Sign-in failed</h1>
    <p class="error-text">${escapeHtml(message)}</p>
    <p><a href="/">Start again</a></p>
  `);
}

// The scopes that release identity claims are shown in ink; everything else
// is a data scope on the Real API, shown in blue.
const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email', 'real.identity']);

function scopeChips(scope) {
  const granted = String(scope || '').split(/\s+/).filter(Boolean);
  if (!granted.length) return '<p class="caption">No scope was granted.</p>';
  return `<ul class="chips">${granted
    .map((s) => `<li class="chip${IDENTITY_SCOPES.has(s) ? '' : ' data'}">${escapeHtml(s)}</li>`)
    .join('')}</ul>`;
}

// The button is "Login with" followed by the wordmark itself — the logo is
// the word. On a light background the black asset cross-fades to the white
// one on hover; on a dark background the white asset is already right.
function loginButton(variant) {
  const logo = variant === 'on-dark'
    ? '<img class="rest" src="/rezen-logo-white.svg" alt="reZEN">'
    : '<img class="rest" src="/rezen-logo-black.svg" alt="reZEN">'
      + '<img class="swap" src="/rezen-logo-white.svg" alt="" aria-hidden="true">';
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

  function ensureSession(req, res) {
    const existing = getSession(req);
    if (existing) return existing;
    const id = randomBytes(24).toString('base64url');
    const data = {};
    sessions.set(id, data);
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
        const session = ensureSession(req, res);
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
        const userinfoRes = await userinfo(discovery, accessToken);
        steps.push(userinfoRes.status === 200 ? 'Userinfo fetched' : `Userinfo call failed (HTTP ${userinfoRes.status})`);
        const identity = userinfoRes.status === 200 && typeof userinfoRes.body === 'object'
          ? { ...claims, ...userinfoRes.body }
          : claims;

        let profile;
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

        session.data.identity = { sub: identity.sub, name: identity.name, email: identity.email, yentaId: identity.yentaId };
        session.data.scope = tokenRes.body.scope || '';
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

      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not found');
    } catch (err) {
      console.error('unexpected error:', err?.message || err);
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('unexpected error');
    }
  };

  return http.createServer(handler);
}
