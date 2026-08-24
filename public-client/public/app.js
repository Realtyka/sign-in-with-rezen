import { apiCall, authorizeUrl, discover, pkce, randomToken, userinfo } from './oidc.js';

const STASH_KEY = 'login-with-rezen:flow';
const SESSION_KEY = 'login-with-rezen:session';
const CHANNEL_NAME = 'login-with-rezen';
const POPUP_NAME = 'login-with-rezen';

let config;
let discovery;
let currentPkce;
let popupHandle;
// The refresh token lives only in this module-level variable — it is never
// written to sessionStorage, and it is gone after a reload (this sample
// does not implement refresh; see the README).
let refreshToken;

const channel = new BroadcastChannel(CHANNEL_NAME);

function $(id) {
  return document.getElementById(id);
}

function showSection(name) {
  $('signed-out').hidden = name !== 'signed-out';
  $('signed-in').hidden = name !== 'signed-in';
  $('error-box').hidden = name !== 'error';
}

function showError(message) {
  $('error-message').textContent = message;
  showSection('error');
}

async function refreshPkce() {
  currentPkce = await pkce();
}

function onLoginClick() {
  const state = randomToken();
  const nonce = randomToken();
  const { verifier, challenge } = currentPkce;
  sessionStorage.setItem(STASH_KEY, JSON.stringify({ state, nonce, verifier }));

  const url = authorizeUrl(discovery, {
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scopes: config.scopes,
    state,
    nonce,
    challenge,
  });

  // The PKCE challenge used above was computed ahead of time (on load, or
  // after the previous attempt) — the digest is async, so it can't happen
  // inline here. This keeps everything up to window.open() synchronous,
  // which popup blockers require. Compute the next pair now, off the
  // critical path, so a second click is synchronous too.
  refreshPkce();

  const popup = window.open(url, POPUP_NAME, 'popup,width=520,height=720');
  if (popup) {
    popupHandle = popup;
    $('status').textContent = 'Complete sign-in in the popup window…';
  } else {
    // Popup blocked — fall back to a full-page redirect through the same
    // authorize URL and the same callback page.
    location.assign(url);
  }
}

function handleResult(msg) {
  if (!msg || msg.type !== 'login-with-rezen') return;
  if (popupHandle && !popupHandle.closed) popupHandle.close();
  popupHandle = undefined;
  refreshToken = msg.refresh_token;
  completeAndRender({
    accessToken: msg.access_token,
    expiresAt: Date.now() + (msg.expires_in || 0) * 1000,
    scope: msg.scope || '',
    claims: msg.claims,
    steps: [...(msg.steps || [])],
  });
}

// Fetches /userinfo and GET /api/v1/users/me, renders the result, and
// mirrors everything but the refresh token into sessionStorage.
async function completeAndRender(session) {
  const steps = [...(session.steps || [])];

  // Identity comes from /userinfo — the id_token proves who signed in (sub),
  // /userinfo carries the claims the granted scopes release.
  let claims = session.claims || {};
  try {
    const res = await userinfo(discovery, session.accessToken);
    steps.push(res.status === 200 ? 'userinfo fetched' : `userinfo call failed (HTTP ${res.status})`);
    if (res.status === 200 && res.body && typeof res.body === 'object') claims = { ...claims, ...res.body };
  } catch (err) {
    steps.push(`userinfo call failed (${err.message})`);
  }

  let profile;
  try {
    const res = await apiCall(config.apiBase, '/api/v1/users/me', session.accessToken);
    steps.push(`/me fetched with x-api-key (status ${res.status})`);
    if (res.status === 200) {
      profile = {
        displayName: res.body.displayName ?? '(not present)',
        type: res.body.type ?? '(not present)',
      };
    }
  } catch (err) {
    steps.push(`/me call failed (${err.message})`);
  }

  const mirror = { ...session, claims, steps, profile, completed: true };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(mirror));
  renderSignedIn(mirror);
}

// The scopes that release identity claims are shown in ink; everything else
// is a data scope on the Real API, shown in blue.
const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email', 'real.identity']);

function scopeChip(scope) {
  const li = document.createElement('li');
  li.className = IDENTITY_SCOPES.has(scope) ? 'chip' : 'chip data';
  li.textContent = scope;
  return li;
}

function renderSignedIn(session) {
  const claims = session.claims || {};
  $('id-sub').textContent = claims.sub ?? '(not present)';
  $('id-name').textContent = claims.name ?? '(not present)';
  $('id-email').textContent = claims.email ?? '(not present)';
  $('id-yentaid').textContent = claims.yentaId ?? '(not present)';
  $('id-scope').replaceChildren(
    ...(session.scope || '').split(/\s+/).filter(Boolean).map(scopeChip),
  );

  const profileTable = $('profile-table');
  const profileSkip = $('profile-skip');
  if (session.profile) {
    $('profile-displayname').textContent = session.profile.displayName;
    $('profile-type').textContent = session.profile.type;
    profileTable.hidden = false;
    profileSkip.hidden = true;
  } else {
    profileTable.hidden = true;
    profileSkip.textContent = 'Not shown — the /me call did not return a profile.';
    profileSkip.hidden = false;
  }

  $('steps').replaceChildren(
    ...(session.steps || []).map((step) => {
      const li = document.createElement('li');
      // A step that reports a failure gets a different marker — the timeline
      // is a record of what happened, not a row of ticks.
      if (/failed/i.test(step)) li.className = 'warn';
      li.textContent = step;
      return li;
    }),
  );

  showSection('signed-in');
}

function logOut() {
  refreshToken = undefined;
  sessionStorage.removeItem(SESSION_KEY);
  $('status').textContent = '';
  showSection('signed-out');
}

async function restoreSession() {
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) {
    showSection('signed-out');
    return;
  }
  let mirror;
  try {
    mirror = JSON.parse(raw);
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    showSection('signed-out');
    return;
  }

  if (mirror.expiresAt && mirror.expiresAt <= Date.now()) {
    // The mirrored access token has expired — start over.
    sessionStorage.removeItem(SESSION_KEY);
    showSection('signed-out');
    return;
  }

  if (mirror.completed) {
    renderSignedIn(mirror);
    return;
  }

  // The redirect fallback lands here on a fresh "/" load with the code
  // already exchanged and the id_token already verified, but userinfo and
  // the API call not made yet — finish the same pipeline the popup uses.
  await completeAndRender(mirror);
}

async function boot() {
  config = (await import('/config.js')).default;
  try {
    discovery = await discover(config.issuer);
  } catch (err) {
    showError(`Could not read the discovery document: ${err.message}`);
    return;
  }
  await refreshPkce();

  // The landing page shows the button on both a light and a dark background.
  // Both are live and start the same flow.
  for (const id of ['login-button', 'login-button-dark']) {
    const button = $(id);
    button.disabled = false;
    button.addEventListener('click', onLoginClick);
  }
  $('logout-link').addEventListener('click', (event) => {
    event.preventDefault();
    logOut();
  });

  await restoreSession();
}

channel.onmessage = (event) => handleResult(event.data);
// The popup may also reach us this way if it still has window.opener —
// only accept same-origin messages.
window.addEventListener('message', (event) => {
  if (event.origin !== location.origin) return;
  handleResult(event.data);
});

boot();
