import { apiCall, authorizeUrl, discover, pkce, randomToken, revoke, userinfo } from './oidc.js';
import { CHANNEL_NAME, POPUP_NAME, SESSION_KEY, STASH_KEY } from './keys.js';

const POPUP_CLOSE_POLL_MS = 500;

let config;
let discovery;
let currentPkce;
let popupHandle;
let popupWatcher;
// The button that started the flow this tab is waiting on — it shows the
// loading state until the popup delivers a result or goes away.
let loadingButton;
// The refresh token lives only in this module-level variable — it is never
// written to sessionStorage, so it is gone after a reload. That is the whole
// reason Disconnect has two shapes: see disconnect() below.
let refreshToken;
// The access token of the session currently on screen. Mirrored into
// sessionStorage too (unlike the refresh token), so it survives a reload —
// it is what Disconnect revokes when the refresh token no longer exists.
let accessToken;
// The state of the flow this tab is waiting on, so a result meant for a
// different tab (or a stale result from a closed popup) is never applied
// here. Restored below from this tab's own stash — the popup's copy of the
// stash is removed once it hands off its result, but the opener's copy
// (this tab's) survives, since sessionStorage is cloned into a popup, not
// shared with it.
let pendingState;
try {
  const stashed = sessionStorage.getItem(STASH_KEY);
  if (stashed) pendingState = JSON.parse(stashed).state;
} catch {
  pendingState = undefined;
}

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

// At most one button is loading at a time: the one that opened the popup.
function setLoading(button) {
  if (loadingButton) {
    loadingButton.classList.remove('is-loading');
    loadingButton.removeAttribute('aria-busy');
  }
  loadingButton = button;
  if (button) {
    button.classList.add('is-loading');
    button.setAttribute('aria-busy', 'true');
  }
}

function onLoginClick(event) {
  // A second click while the popup is already open would re-navigate that
  // named window with a fresh state/nonce/verifier while the popup's own
  // (cloned) copy of the stash still holds the first one — the callback
  // then rejects its own state. Focus the existing popup instead of
  // starting a second flow.
  if (popupHandle && !popupHandle.closed) {
    popupHandle.focus();
    setLoading(undefined);
    return;
  }

  const state = randomToken();
  const nonce = randomToken();
  const { verifier, challenge } = currentPkce;
  pendingState = state;
  // popup: true until the popup-blocked branch below overwrites it. This is
  // how callback.js decides whether it's finishing a popup flow — reading
  // window.opener or window.name isn't reliable once the issuer's pages set
  // Cross-Origin-Opener-Policy: same-origin (see the README).
  sessionStorage.setItem(STASH_KEY, JSON.stringify({ state, nonce, verifier, popup: true }));

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

  if (popupWatcher) clearInterval(popupWatcher);
  const popup = window.open(url, POPUP_NAME, 'popup,width=520,height=720');
  if (popup) {
    popupHandle = popup;
    setLoading(event.currentTarget);
    $('status').textContent = 'Complete sign-in in the popup window…';
    // If the user closes the popup before it delivers a result, don't leave
    // the status message showing forever.
    popupWatcher = setInterval(() => {
      if (!popup.closed) return;
      clearInterval(popupWatcher);
      popupWatcher = undefined;
      if (popupHandle === popup) popupHandle = undefined;
      // Only the status message is cleared here. Under
      // Cross-Origin-Opener-Policy, popup.closed reports true the moment the
      // popup navigates to the issuer — long before it has a result to
      // deliver — so this is not evidence the flow is over. Clearing
      // pendingState or the stash here would make handleResult() ignore a
      // correct result that is still on its way over the BroadcastChannel.
      setLoading(undefined);
      $('status').textContent = '';
    }, POPUP_CLOSE_POLL_MS);
  } else {
    // Popup blocked — fall back to a full-page redirect through the same
    // authorize URL and the same callback page. Overwrite the stash so
    // callback.js (which runs in this same tab next) knows this is the
    // redirect fallback, not a popup.
    sessionStorage.setItem(STASH_KEY, JSON.stringify({ state, nonce, verifier, popup: false }));
    location.assign(url);
  }
}

function handleResult(msg) {
  if (!msg || msg.type !== 'login-with-rezen') return;
  // Ignore a result for a flow this tab didn't start (or already finished)
  // — the channel delivers to every same-origin tab, not just this one.
  if (!pendingState || msg.state !== pendingState) return;
  pendingState = undefined;
  sessionStorage.removeItem(STASH_KEY);
  if (popupWatcher) {
    clearInterval(popupWatcher);
    popupWatcher = undefined;
  }
  if (popupHandle && !popupHandle.closed) popupHandle.close();
  popupHandle = undefined;
  refreshToken = msg.refresh_token;
  // Tell the popup its result was received — it waits briefly for this
  // before closing itself (see callback.js).
  channel.postMessage({ type: 'login-with-rezen:ack', state: msg.state });
  // The button stays in its loading state until the result is on the page.
  completeAndRender({
    accessToken: msg.access_token,
    // A missing expires_in means "no expiry known", not "expired now".
    expiresAt: typeof msg.expires_in === 'number' ? Date.now() + msg.expires_in * 1000 : undefined,
    scope: msg.scope || '',
    claims: msg.claims,
    steps: [...(msg.steps || [])],
  }).finally(() => setLoading(undefined));
}

// Fetches /userinfo and GET /api/v1/users/me, renders the result, and
// mirrors everything but the refresh token into sessionStorage.
async function completeAndRender(session) {
  const steps = [...(session.steps || [])];

  // Identity comes from /userinfo — the id_token proves who signed in (sub),
  // /userinfo carries the claims the granted scopes release. OIDC Core
  // 5.3.2: only trust /userinfo when its sub matches the verified id_token
  // — otherwise keep the id_token's claims as-is.
  let claims = session.claims || {};
  try {
    const res = await userinfo(discovery, session.accessToken);
    if (res.status !== 200) {
      steps.push(`userinfo call failed (HTTP ${res.status})`);
    } else if (res.body && typeof res.body === 'object' && res.body.sub === claims.sub) {
      claims = { ...claims, ...res.body };
      steps.push('userinfo fetched');
    } else {
      steps.push('Userinfo ignored — sub did not match the ID token');
    }
  } catch (err) {
    steps.push(`userinfo call failed (${err.message})`);
  }

  let profile;
  try {
    const res = await apiCall(config.apiBase, '/api/v1/users/me', session.accessToken);
    if (res.status === 200) {
      profile = {
        displayName: res.body.displayName ?? '(not present)',
        type: res.body.type ?? '(not present)',
      };
      steps.push('/me fetched with x-api-key (200)');
    } else {
      steps.push(`/me call failed (HTTP ${res.status})`);
    }
  } catch (err) {
    steps.push(`/me call failed (${err.message})`);
  }

  const mirror = { ...session, claims, steps, profile, completed: true };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(mirror));
  accessToken = mirror.accessToken;
  renderSignedIn(mirror);
}

// The scopes that release identity claims get the neutral badge; everything
// else is a data scope on the Real API and gets the brand badge.
const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email', 'real.identity']);

function scopeBadge(scope) {
  const li = document.createElement('li');
  li.className = IDENTITY_SCOPES.has(scope) ? 'badge' : 'badge brand';
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
    ...(session.scope || '').split(/\s+/).filter(Boolean).map(scopeBadge),
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

// What the landing says after a disconnect. The session is gone by then, so
// this line is where the outcome is reported — including which token was
// revoked, and a revoke that did not succeed.
const DISCONNECT_NOTICES = {
  refresh_token: 'Disconnected — the refresh token was revoked, and with it the API keys minted under it.',
  access_token: 'Disconnected — this tab held no refresh token after the reload, so the access token was revoked instead.',
  failed: 'Signed out, but the revoke call did not succeed — your tokens may still be live at reZEN.',
  none: 'Signed out — there was no token left in this tab to revoke.',
};

function showLandingNotice(text) {
  $('landing-notice-text').textContent = text || '';
  $('landing-notice').hidden = !text;
}

// Sign out is local and stops here: this tab forgets both tokens, and
// nothing is said to reZEN. The tokens themselves stay live there until
// they expire — that is what Disconnect is for.
function signOut() {
  refreshToken = undefined;
  accessToken = undefined;
  sessionStorage.removeItem(SESSION_KEY);
  $('status').textContent = '';
  showLandingNotice('');
  showSection('signed-out');
}

// Disconnect is the guide's §8 action: revoke first, then forget.
//
// A refresh token takes its whole family and the API keys minted under it
// with it, so that is what we send when this tab still has one. After a
// reload it does not — the refresh token is deliberately never persisted —
// and the access token is then the only credential left to revoke, which
// kills that one key. The local session is cleared either way: a revoke
// that fails must not leave the user apparently signed in.
async function disconnect(link) {
  const token = refreshToken || accessToken;
  const tokenTypeHint = refreshToken ? 'refresh_token' : 'access_token';
  if (!token) {
    signOut();
    showLandingNotice(DISCONNECT_NOTICES.none);
    return;
  }
  link.setAttribute('aria-disabled', 'true');
  let outcome = tokenTypeHint;
  try {
    const res = await revoke(discovery, { clientId: config.clientId, token, tokenTypeHint });
    if (res.status !== 200) outcome = 'failed';
  } catch {
    // Network failure, or an issuer that publishes no revocation_endpoint.
    // The error is never logged: the token is in the request that made it.
    outcome = 'failed';
  }
  link.removeAttribute('aria-disabled');
  signOut();
  showLandingNotice(DISCONNECT_NOTICES[outcome]);
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
    accessToken = mirror.accessToken;
    renderSignedIn(mirror);
    return;
  }

  // The redirect fallback lands here on a fresh "/" load with the code
  // already exchanged and the id_token already verified, but userinfo and
  // the API call not made yet — finish the same pipeline the popup uses.
  await completeAndRender(mirror);
}

async function boot() {
  try {
    config = (await import('/config.js')).default;
  } catch (err) {
    showError(`Could not load the app configuration: ${err.message}`);
    return;
  }
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
  $('sign-out-link').addEventListener('click', (event) => {
    event.preventDefault();
    signOut();
  });
  $('disconnect-link').addEventListener('click', (event) => {
    event.preventDefault();
    disconnect(event.currentTarget);
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
