import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiCall, authorizeUrl, discover, exchangeCode, pkce, revoke, userinfo, verifyIdToken } from './oidc.js';

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

// The CSRF defence for the state-changing routes, in full: they are POST
// only, the session cookie is SameSite=Lax (so a cross-site POST arrives
// without it), and the request must say it came from this origin.
// Sec-Fetch-Site is sent by every current browser; Origin is the fallback
// for anything that isn't one. Neither header present is a non-browser
// caller (curl, the test suite), which no cross-site page can impersonate.
function isSameOrigin(req, url) {
  const site = req.headers['sec-fetch-site'];
  if (site) return site === 'same-origin' || site === 'none';
  const origin = req.headers.origin;
  return !origin || origin === url.origin;
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
/* Sign in with reZEN — sample client.
 *
 * The reZEN product look: white surfaces, a 1px grey border as the resting
 * edge, grey type, and one blue accent that does all the work. No gradients,
 * no textures, no shadows — spacing and that hairline border do the
 * separating. Values the flow returns are set in mono; everything else is the
 * body face.
 *
 * Self-contained by design — no webfonts, no icon sets, no external request
 * of any kind. The page renders offline: Inter when the system already has
 * it, the platform sans otherwise.
 */

:root {
  /* design tokens */
  --blue-50: #edf4ff;
  --blue-100: #ddebff;
  --blue-200: #c2d8ff;
  --blue-500: #4967fd;
  --blue-600: #3848f3;
  --blue-700: #2c39d6;
  --blue-900: #273288;
  --blue-950: #171c4f;

  --red-50: #fff1f2;
  --red-200: #ffccd3;
  --red-500: #f84c6c;

  --grey-50: #f8fafc;
  --grey-100: #f1f5f9;
  --grey-200: #e2e8f0;
  --grey-300: #cbd5e1;
  --grey-400: #94a3b8;
  --grey-500: #64748b;
  --grey-700: #334155;
  --grey-800: #1e293b;
  --grey-950: #020617;

  --white: #ffffff;
  --black: #1d1d1d;

  /* semantic aliases */
  --surface-primary: var(--white);
  --surface-secondary: var(--grey-50);
  --surface-dark: var(--grey-950);
  --border-default: var(--grey-200);
  --border-focus: var(--blue-500);
  --text-primary: var(--grey-950);
  --text-secondary: var(--grey-700);
  --text-tertiary: var(--grey-500);
  --text-brand: var(--blue-500);
  --text-inverse: var(--white);

  /* type */
  --font-family-body: "Inter", -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  --font-family-head: var(--font-family-body);
  --font-family-mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
  --fs-h1: 30px;
  --lh-h1: 36px;
  --fs-body: 16px;
  --fs-body-sm: 14px;
  --fs-caption: 12px;

  /* shape */
  --radius: 6px;
  --radius-xl: 12px;
}

@media (max-width: 767px) {
  :root {
    --fs-h1: 24px;
    --lh-h1: 32px;
    --fs-body: 14px;
    --fs-body-sm: 12px;
  }
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  min-height: 100vh;
  color: var(--text-primary);
  font-family: var(--font-family-body);
  font-size: var(--fs-body);
  font-weight: 400;
  line-height: 1.5;
  background-color: var(--surface-secondary);
  -webkit-font-smoothing: antialiased;
}

/* ---- layout: one left-aligned content column ---- */
.wrap {
  max-width: 1120px;
  margin: 0 auto;
  padding: clamp(40px, 8vh, 88px) 24px 72px;
}
.col { max-width: 640px; }
.wide { width: 100%; }
/* The landing is two panels and nothing else, so it centres itself on a tall
 * viewport. Browsers without :has() simply leave it top-aligned. */
.wrap:has(> .wide:not([hidden])) {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

/* ---- type ---- */
/* The page mark keeps clear space of at least its own height on every side. */
.brandmark {
  display: block;
  height: 24px;
  width: auto;
  margin: 0 0 24px;
}

h1,
.display {
  margin: 0 0 12px;
  font-family: var(--font-family-head);
  font-weight: 600;
  font-size: var(--fs-h1);
  line-height: var(--lh-h1);
  letter-spacing: -.01em;
  color: inherit;
}
.display { display: block; }

p { margin: 0 0 16px; }

.caption {
  margin: 12px 0 0;
  color: var(--text-tertiary);
  font-size: var(--fs-caption);
  line-height: 16px;
}

/* Section labels: the smallest heading step, over a hairline divider. */
.section-label {
  margin: 32px 0 16px;
  padding-top: 24px;
  border-top: 1px solid var(--border-default);
  font-family: var(--font-family-head);
  font-weight: 600;
  font-size: 14px;
  line-height: 20px;
  color: var(--text-primary);
}

a {
  color: var(--text-brand);
  font-weight: 500;
  text-decoration: none;
}
a:hover { text-decoration: underline; }
a:focus-visible {
  outline: 2px solid var(--border-focus);
  outline-offset: 2px;
  border-radius: var(--radius);
}

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
  border: 1px solid transparent;
  border-radius: var(--radius-xl);
  padding: clamp(24px, 3vw, 40px);
}
.panel-light {
  background: var(--surface-primary);
  border-color: var(--border-default);
  color: var(--text-primary);
}
.panel-dark {
  background: var(--surface-dark);
  border-color: var(--surface-dark);
  color: var(--text-inverse);
}
.panel-logo { display: block; height: 24px; width: auto; margin: 0 0 24px; }
.panel-kicker {
  margin: 0 0 8px;
  color: var(--text-tertiary);
  font-size: var(--fs-caption);
  line-height: 16px;
}
.panel-copy {
  margin: 0 0 24px;
  max-width: 42ch;
  color: var(--text-secondary);
}
/* On the dark panel the quiet greys lift a step so they stay legible. */
.panel-dark .panel-kicker,
.panel-dark .caption,
.panel-dark .styles-label,
.panel-dark .styles-note { color: var(--grey-400); }
.panel-dark .panel-copy { color: var(--grey-300); }

/* ---- the button: the reZEN sign-in button ----
 * Two variants (filled, outline), three fill styles (navy — the default —,
 * rezen, neutral), four sizes (xs, s, m, l) and the states hover, pressed,
 * loading and disabled. Fill styles and sizes are custom properties on a
 * modifier class, so one rule set draws every combination. The outline
 * variant is the same in every fill style. These colours belong to the
 * button and to nothing else on the page. */
.cta { margin: 0; }

.rezen-btn,
.rezen-btn.navy {
  --rezen-btn-fill: #050e3d;
  --rezen-btn-fill-hover: var(--blue-950);
  --rezen-btn-fill-active: var(--blue-900);
}
.rezen-btn.rezen {
  --rezen-btn-fill: var(--blue-500);
  --rezen-btn-fill-hover: var(--blue-600);
  --rezen-btn-fill-active: var(--blue-700);
}
.rezen-btn.neutral {
  --rezen-btn-fill: #000000;
  --rezen-btn-fill-hover: var(--grey-800);
  --rezen-btn-fill-active: var(--grey-700);
}

/* Sizes: height, inset from the outer edge (the 1px border is inside it),
 * label size, wordmark height, and the gap between label, wordmark and
 * spinner. Medium is the default. */
.rezen-btn,
.rezen-btn.m {
  --rezen-btn-height: 44px;
  --rezen-btn-padding: 0 15px;
  --rezen-btn-font-size: 16px;
  --rezen-btn-logo: 24px;
  --rezen-btn-gap: 8px;
}
.rezen-btn.xs {
  --rezen-btn-height: 28px;
  --rezen-btn-padding: 0 11px 0 7px;
  --rezen-btn-font-size: 14px;
  --rezen-btn-logo: 18px;
  --rezen-btn-gap: 4px;
}
.rezen-btn.s {
  --rezen-btn-height: 38px;
  --rezen-btn-padding: 0 15px;
  --rezen-btn-font-size: 14px;
  --rezen-btn-logo: 20px;
  --rezen-btn-gap: 6px;
}
.rezen-btn.l {
  --rezen-btn-height: 52px;
  --rezen-btn-padding: 0 23px;
  --rezen-btn-font-size: 18px;
  --rezen-btn-logo: 24px;
  --rezen-btn-gap: 8px;
}

.rezen-btn {
  --rezen-btn-outline-bg: var(--white);
  --rezen-btn-outline-bg-hover: var(--grey-50);
  --rezen-btn-outline-bg-active: var(--grey-100);
  --rezen-btn-outline-border: var(--grey-200);
  --rezen-btn-outline-border-hover: var(--grey-300);
  --rezen-btn-outline-ink: var(--grey-950);

  display: inline-flex;
  align-items: center;
  gap: var(--rezen-btn-gap);
  box-sizing: border-box;
  height: var(--rezen-btn-height);
  padding: var(--rezen-btn-padding);
  border: 1px solid transparent;
  border-radius: var(--radius);
  font-family: var(--font-family-body);
  font-size: var(--rezen-btn-font-size);
  font-weight: 500;
  line-height: 1;
  letter-spacing: 0;
  white-space: nowrap;
  text-decoration: none;
  cursor: pointer;
  transition: background-color .15s ease, border-color .15s ease;
}
.rezen-btn:hover { text-decoration: none; }
.rezen-btn-label { color: inherit; }
/* The wordmark is an image, never recoloured: the white asset on the filled
 * variant, the black asset on the outline variant. */
.rezen-btn-logo { display: block; height: var(--rezen-btn-logo); width: auto; }
.rezen-btn:focus-visible { outline: 2px solid var(--border-focus); outline-offset: 2px; }

.rezen-btn.filled {
  background: var(--rezen-btn-fill);
  border-color: var(--rezen-btn-fill);
  color: var(--text-inverse);
}
.rezen-btn.filled:hover {
  background: var(--rezen-btn-fill-hover);
  border-color: var(--rezen-btn-fill-hover);
}
.rezen-btn.filled:active {
  background: var(--rezen-btn-fill-active);
  border-color: var(--rezen-btn-fill-active);
}
.rezen-btn.outline {
  background: var(--rezen-btn-outline-bg);
  border-color: var(--rezen-btn-outline-border);
  color: var(--rezen-btn-outline-ink);
}
.rezen-btn.outline:hover {
  background: var(--rezen-btn-outline-bg-hover);
  border-color: var(--rezen-btn-outline-border-hover);
}
.rezen-btn.outline:active {
  background: var(--rezen-btn-outline-bg-active);
  border-color: var(--rezen-btn-outline-border-hover);
}

/* Loading and disabled: the resting colours at half opacity. Loading adds a
 * spinner on the left and takes the pointer away; set aria-busy with it. */
.rezen-btn.is-loading,
.rezen-btn:disabled,
.rezen-btn[aria-disabled="true"] { opacity: .5; }
.rezen-btn:disabled,
.rezen-btn[aria-disabled="true"] { cursor: default; }
.rezen-btn.is-loading { pointer-events: none; }
.rezen-btn.filled.is-loading,
.rezen-btn.filled:disabled,
.rezen-btn.filled[aria-disabled="true"] {
  background: var(--rezen-btn-fill);
  border-color: var(--rezen-btn-fill);
}
.rezen-btn.outline.is-loading,
.rezen-btn.outline:disabled,
.rezen-btn.outline[aria-disabled="true"] {
  background: var(--rezen-btn-outline-bg);
  border-color: var(--rezen-btn-outline-border);
}
.rezen-btn.is-loading::before {
  content: "";
  flex: none;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 2px solid transparent;
  border-color: color-mix(in srgb, currentColor 30%, transparent);
  border-top-color: currentColor;
  animation: rezen-btn-spin .8s linear infinite;
}
@keyframes rezen-btn-spin {
  to { transform: rotate(1turn); }
}
/* The mark-and-text layout: the bracket mark on the left, then the whole
 * label as text — no wordmark image. Same heights, radius, border and type;
 * a wider gap. The mark takes the label colour on the filled variant and the
 * near-black on the outline variant. */
.rezen-btn.icon-left,
.rezen-btn.icon-left.m,
.rezen-btn.icon-left.l { --rezen-btn-gap: 12px; --rezen-btn-mark: 16px; }
.rezen-btn.icon-left.s { --rezen-btn-gap: 8px; --rezen-btn-mark: 16px; }
.rezen-btn.icon-left.xs { --rezen-btn-gap: 6px; --rezen-btn-mark: 14px; --rezen-btn-padding: 0 11px; }
.rezen-btn-mark { display: block; flex: none; height: var(--rezen-btn-mark, 16px); width: auto; }
.rezen-btn.outline .rezen-btn-mark { color: var(--black); }

/* A specimen: drawn like the button, but not one — no pointer, no states. */
.rezen-btn.specimen { pointer-events: none; }

/* Under each call to action: styles that differ from it. */
.styles { margin: 24px 0 0; }
.styles-label,
.styles-note {
  margin: 0 0 12px;
  color: var(--text-tertiary);
  font-size: var(--fs-caption);
  line-height: 16px;
}
.styles-note { margin: 12px 0 0; }
.styles-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

/* ---- the plain button: used where the page acts on itself ---- */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 44px;
  padding: 0 16px;
  border: 1px solid transparent;
  border-radius: var(--radius);
  font-family: var(--font-family-body);
  font-size: 16px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  text-decoration: none;
  cursor: pointer;
  transition: background-color .15s ease, border-color .15s ease;
}
.btn.s { height: 38px; font-size: 14px; }
.btn:hover { text-decoration: none; }
.btn:focus-visible { outline: 2px solid var(--border-focus); outline-offset: 2px; }
/* Ghost: the quietest step. Pulled left by its own padding so the label
 * lines up with the column. */
.btn-ghost {
  margin-left: -16px;
  background: transparent;
  color: var(--text-brand);
}
.btn-ghost:hover { background: var(--blue-50); }
.btn-ghost:active { background: var(--blue-100); }

/* ---- values the flow returns: always mono ---- */
table.kv {
  border-collapse: collapse;
  width: 100%;
  font-family: var(--font-family-mono);
  font-size: 13px;
  line-height: 20px;
}
table.kv td {
  padding: 10px 0;
  border-bottom: 1px solid var(--border-default);
  vertical-align: top;
}
table.kv tr:last-child td { border-bottom: 0; }
table.kv td:first-child {
  width: 34%;
  padding-right: 16px;
  color: var(--text-tertiary);
}
table.kv td:last-child { color: var(--text-primary); word-break: break-word; }

.card {
  background: var(--surface-primary);
  border: 1px solid var(--border-default);
  border-radius: var(--radius);
  padding: 2px 16px;
}

/* ---- granted scope: one badge per scope ----
 * The scopes that release identity claims are neutral; everything else is a
 * data scope on the Real API and carries the brand tone. */
ul.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.badge {
  display: inline-flex;
  align-items: center;
  height: 28px;
  padding: 0 10px;
  border: 1px solid var(--border-default);
  border-radius: var(--radius);
  background: var(--surface-primary);
  color: var(--text-primary);
  font-size: var(--fs-caption);
  line-height: 1;
  white-space: nowrap;
}
.badge.brand {
  background: var(--blue-50);
  border-color: var(--blue-200);
  color: var(--blue-900);
}

/* ---- what happened: a timeline, one marker per step ---- */
ol.steps {
  list-style: none;
  margin: 0;
  padding: 2px 0 2px 28px;
  border-left: 1px solid var(--border-default);
}
ol.steps li {
  position: relative;
  margin: 0 0 12px;
  color: var(--text-secondary);
  font-size: var(--fs-body-sm);
  line-height: 20px;
}
ol.steps li:last-child { margin-bottom: 0; }
ol.steps li::before {
  content: "✓";
  position: absolute;
  left: -39px;
  top: 0;
  width: 18px;
  height: 18px;
  display: grid;
  place-items: center;
  border: 1px solid var(--border-default);
  border-radius: var(--radius);
  background: var(--surface-primary);
  color: var(--text-brand);
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
}
/* A step that reports a failure gets the danger marker. */
ol.steps li.warn::before {
  content: "!";
  background: var(--red-50);
  border-color: var(--red-200);
  color: var(--red-500);
}

/* ---- the two ways out, side by side, both quiet ---- */
.actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
  margin: 32px 0 0 -16px;
}
.actions form { margin: 0; }
.actions .btn-ghost { margin-left: 0; }
.actions-note {
  max-width: 64ch;
  margin: 8px 0 0;
  color: var(--text-tertiary);
  font-size: var(--fs-caption);
  line-height: 18px;
}

/* ---- an inline alert: tinted, bordered, dark type ---- */
.alert {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  margin: 0 0 24px;
  padding: 12px 16px;
  border: 1px solid var(--border-default);
  border-radius: var(--radius);
  background: var(--surface-primary);
  color: var(--text-secondary);
  font-size: var(--fs-body-sm);
  line-height: 20px;
}
.alert p { margin: 0; }
.alert-icon {
  flex: none;
  width: 16px;
  height: 16px;
  margin-top: 2px;
  color: var(--text-tertiary);
}
.alert-danger {
  background: var(--red-50);
  border-color: var(--red-200);
}
.alert-danger .alert-icon { color: var(--red-500); }

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

// The alert icon, drawn in the alert's own colour.
const ALERT_ICON = '<svg class="alert-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
  + '<path fill="currentColor" d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0Zm0 3.4a.9.9 0 0 1 .9.9v4a.9.9 0'
  + ' 0 1-1.8 0v-4a.9.9 0 0 1 .9-.9Zm0 7.1a1.05 1.05 0 1 1 0 2.1 1.05 1.05 0 0 1 0-2.1Z"/></svg>';

function errorPage(message) {
  return layout('Sign-in failed', `
    <img class="brandmark" src="/rezen-logo-black.svg" alt="reZEN">
    <h1>Sign-in failed</h1>
    <div class="alert alert-danger" role="alert">${ALERT_ICON}<p>${escapeHtml(message)}</p></div>
    <p><a href="/">Start again</a></p>
  `);
}

// The scopes that release identity claims get the neutral badge; everything
// else is a data scope on the Real API and gets the brand badge.
const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email', 'real.identity']);

function scopeBadges(scope) {
  const granted = String(scope || '').split(/\s+/).filter(Boolean);
  if (!granted.length) return '<p class="caption">No scope was granted.</p>';
  return `<ul class="badges">${granted
    .map((s) => `<li class="badge${IDENTITY_SCOPES.has(s) ? '' : ' brand'}">${escapeHtml(s)}</li>`)
    .join('')}</ul>`;
}

// The button is "Sign in with" followed by the wordmark itself: the white
// asset on the filled variant, the black asset on the outline variant. The
// page has no script (its policy allows none), so the link is a plain link —
// the loading and disabled states are in the stylesheet for an app that has
// somewhere to set them.
function loginButton(variant, style = 'navy', size = 'l') {
  const logo = variant === 'filled' ? 'white' : 'black';
  return `<a class="rezen-btn ${variant} ${style} ${size}" href="/sign-in" aria-label="Sign in with reZEN">`
    + '<span class="rezen-btn-label">Sign in with</span>'
    + `<img class="rezen-btn-logo" src="/rezen-logo-${logo}.svg" alt="reZEN"></a>`;
}

// The bracket mark of the mark-and-text layout, drawn in the label colour.
const MARK = '<svg class="rezen-btn-mark" viewBox="0 0 11.78 16" aria-hidden="true" focusable="false">'
  + '<path fill="currentColor" d="M7.25 0v1.81H1.81v10.87H0V0Zm-2.72 16v-1.81h5.44V3.32h1.81V16Z"/></svg>';

// A specimen: drawn like the button, but not one. Either the wordmark layout
// or the mark-and-text layout, in any variant and fill style.
function specimen(variant, style, layout = 'logo') {
  const logo = variant === 'filled' ? 'white' : 'black';
  const inner = layout === 'mark'
    ? `${MARK}<span class="rezen-btn-label">Sign in with reZEN</span>`
    : `<span class="rezen-btn-label">Sign in with</span><img class="rezen-btn-logo" src="/rezen-logo-${logo}.svg" alt="">`;
  return `<span class="rezen-btn specimen ${variant} ${style} s${layout === 'mark' ? ' icon-left' : ''}">${inner}</span>`;
}

// Under each call to action: styles that differ from it. The outline variant
// is the same in every fill style, so the dark panel says so rather than
// repeating it.
function otherStyles(variant) {
  const row = variant === 'filled'
    ? [specimen('filled', 'rezen'), specimen('filled', 'neutral'), specimen('filled', 'navy', 'mark')]
    : [specimen('outline', 'navy', 'mark'), specimen('filled', 'rezen')];
  const note = variant === 'filled' ? '' : '<p class="styles-note">Outline is the same in every fill style</p>';
  return '<div class="styles" aria-hidden="true"><p class="styles-label">Other styles</p>'
    + `<div class="styles-row">${row.join('')}</div>${note}</div>`;
}

// Two ways out, and they are not the same thing.
//
// "Sign out" ends this app's session and nothing else: the server-side
// session — and every token in it — is dropped, and the user's tokens at
// reZEN are left alone. "Disconnect" is the guide's §8 action: it calls
// /revoke first, so the refresh token family and the API keys minted under
// it stop working at reZEN, and then ends the session too.
//
// Both are POSTs from a real form, not links. They change server state, and
// a GET that changes state is a GET any other site can make on the user's
// behalf with an <img> tag. The page carries no script (its own policy
// allows none), so a plain form is the whole mechanism.
const SIGNED_IN_ACTIONS = `
      <div class="actions">
        <form method="post" action="/sign-out"><button class="btn btn-ghost s" type="submit">Sign out</button></form>
        <form method="post" action="/disconnect"><button class="btn btn-ghost s" type="submit">Disconnect</button></form>
      </div>
      <p class="actions-note">Sign out ends this app&rsquo;s session on this server and leaves your reZEN
      tokens alone. Disconnect also revokes them at reZEN, so this app&rsquo;s access stops working —
      your consent is kept, so signing in again does not ask you to approve anything twice.</p>`;

function homePage(sessionData, notice) {
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
      <img class="brandmark" src="/rezen-logo-black.svg" alt="reZEN">
      <h1>Signed in with reZEN</h1>
      <h2 class="section-label">Identity</h2>
      ${identityTable}
      <h2 class="section-label">Granted scope</h2>
      ${scopeBadges(sessionData.scope)}
      ${profileBlock}
      <h2 class="section-label">What happened</h2>
      <ol class="steps">${steps}</ol>
      ${SIGNED_IN_ACTIONS}
    `);
  }
  return layout('Sign in with reZEN', `
    ${notice ? `<div class="alert" role="status">${ALERT_ICON}<p>${escapeHtml(notice)}</p></div>` : ''}
    <div class="panels">
      <div class="panel panel-light reveal">
        <img class="panel-logo" src="/rezen-logo-black.svg" alt="reZEN">
        <p class="panel-kicker">On a light background</p>
        <h1>Sign in with reZEN</h1>
        <p class="panel-copy">This sample runs the authorization code flow with PKCE against a
        reZEN OIDC issuer, verifies your identity, and calls one Real API on your behalf.</p>
        <p class="cta">${loginButton('filled')}</p>
        <p class="caption">Sign in with your reZEN account to continue</p>
        ${otherStyles('filled')}
      </div>
      <div class="panel panel-dark reveal">
        <img class="panel-logo" src="/rezen-logo-white.svg" alt="reZEN">
        <p class="panel-kicker">On a dark background</p>
        <h2 class="display">Sign in with reZEN</h2>
        <p class="panel-copy">The same flow, the same client, the same button — drawn for a dark
        page. Either button starts the sign-in.</p>
        <p class="cta">${loginButton('outline')}</p>
        <p class="caption">Sign in with your reZEN account to continue</p>
        ${otherStyles('outline')}
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

// Sessions older than this are swept on every /sign-in; the map itself is
// capped so an endless stream of uncookied /sign-in calls can't grow it
// without bound — both are sample-scale limits, not a real eviction policy.
const SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000;
const SESSION_CAP = 1000;

// What the landing page says after a disconnect. The session is gone by
// then, so this line is where a revoke that failed gets reported — the local
// session is dropped either way, but the user is told the difference.
const DISCONNECT_NOTICES = {
  ok: 'Disconnected — your app’s access was revoked.',
  failed: 'Signed out, but the revoke call did not succeed — your tokens may still be live at reZEN.',
};

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

  // Always mints a fresh session id — /sign-in is where sign-in starts, and a
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
      if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname === '/') {
        const session = getSession(req);
        const html = homePage(session?.data, DISCONNECT_NOTICES[url.searchParams.get('disconnected')]);
        if (req.method === 'HEAD') {
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': Buffer.byteLength(html),
            ...SECURITY_HEADERS,
          });
          return res.end();
        }
        return sendHtml(res, html);
      }

      if (req.method === 'GET' && LOGOS[url.pathname]) {
        return sendSvg(res, LOGOS[url.pathname]);
      }

      if (req.method === 'GET' && url.pathname === '/sign-in') {
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

        // state is checked before anything else in the query string is
        // trusted — including error — so a crafted /callback?error=...
        // link can't show this session the issuer's error page for a
        // sign-in it never started.
        const flow = session.data.flow;
        if (!flow || url.searchParams.get('state') !== flow.state) {
          return sendHtml(res, errorPage('The state parameter did not match — start again.'), 400);
        }

        // state really is one-time: the flow is spent the moment a callback
        // presents the matching value, whether the rest of it succeeds or
        // fails. Leaving it in place on a failure would let the same state
        // be replayed at this callback until the session aged out.
        session.data.flow = undefined;

        const errParam = url.searchParams.get('error');
        if (errParam) {
          return sendHtml(
            res,
            errorPage(mapAuthorizeError(errParam, url.searchParams.get('error_description'))),
            400,
          );
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
        // Both tokens are kept server-side for the life of the session —
        // this is the thing a confidential client is for. They are what
        // /disconnect revokes; neither is ever rendered or logged.
        session.data.accessToken = accessToken;
        session.data.refreshToken = tokenRes.body.refresh_token;

        return redirect(res, '/');
      }

      // Both state-changing routes are POST and same-origin only; see
      // isSameOrigin above. A GET says so rather than 404-ing, because a
      // GET here is usually a bookmarked link from an older version.
      if (url.pathname === '/sign-out' || url.pathname === '/disconnect') {
        if (req.method !== 'POST') {
          res.writeHead(405, { Allow: 'POST', 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
          return res.end('use POST — this route changes state');
        }
        if (!isSameOrigin(req, url)) {
          res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
          return res.end('cross-site request refused');
        }
        req.resume(); // the forms carry no fields; drain the body and move on
        const session = getSession(req);
        res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');

        // Sign out is local and stops here: the session and every token in
        // it are dropped, and nothing is said to reZEN.
        if (url.pathname === '/sign-out') {
          if (session) sessions.delete(session.id);
          return redirect(res, '/');
        }

        // Disconnect is the guide's §8 action. Revoke the refresh token —
        // that takes its whole family and the API keys minted under it with
        // it — and fall back to the access token if this session somehow
        // holds no refresh token. Either way the local session goes: a
        // revoke that fails must not leave the user apparently signed in.
        if (!session) return redirect(res, '/');
        const { refreshToken, accessToken } = session.data;
        const token = refreshToken || accessToken;
        let outcome = 'ok';
        if (token) {
          try {
            const discovery = await getDiscovery();
            const revokeRes = await revoke(discovery, {
              clientId: config.clientId,
              clientSecret: config.clientSecret,
              token,
              tokenTypeHint: refreshToken ? 'refresh_token' : 'access_token',
            });
            if (revokeRes.status !== 200) outcome = 'failed';
          } catch {
            // Network failure, discovery failure, an issuer that publishes
            // no revocation_endpoint — the message is never logged, because
            // the token is in the request that produced it.
            outcome = 'failed';
          }
        }
        sessions.delete(session.id);
        return redirect(res, `/?disconnected=${outcome}`);
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
