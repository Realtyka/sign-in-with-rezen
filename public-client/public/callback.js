// The redirect target for /authorize. Runs in the popup window, or in the
// main tab when the popup was blocked and app.js fell back to a full-page
// redirect — the code below handles both the same way.
import { discover, exchangeCode, verifyIdToken } from './oidc.js';

const STASH_KEY = 'login-with-rezen:flow';
const SESSION_KEY = 'login-with-rezen:session';
const CHANNEL_NAME = 'login-with-rezen';

function showMessage(text) {
  document.getElementById('message').textContent = text;
}

// The same page carries the failure: the headline changes, the progress bar
// stops, and the "Start again" link appears. No second template.
function showFailure(text) {
  document.getElementById('headline').textContent = 'Sign-in failed';
  document.getElementById('message').textContent = text;
  document.body.classList.add('is-error');
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
  };
  return known[err] || `Token exchange failed${err ? `: ${err}` : ''}.`;
}

async function run() {
  const config = (await import('/config.js')).default;
  const params = new URLSearchParams(location.search);

  const errParam = params.get('error');
  if (errParam) {
    showFailure(mapAuthorizeError(errParam, params.get('error_description')));
    return;
  }

  const raw = sessionStorage.getItem(STASH_KEY);
  if (!raw) {
    showFailure('No sign-in in progress — start again from the main page.');
    return;
  }
  let stash;
  try {
    stash = JSON.parse(raw);
  } catch {
    showFailure('The saved sign-in request was unreadable — start again.');
    return;
  }

  if (params.get('state') !== stash.state) {
    showFailure('The state parameter did not match — start again.');
    return;
  }
  if (params.get('iss') !== config.issuer) {
    showFailure('The issuer on the callback did not match — start again.');
    return;
  }

  let discovery;
  try {
    discovery = await discover(config.issuer);
  } catch (err) {
    showFailure(`Could not read the discovery document: ${err.message}`);
    return;
  }

  const tokenRes = await exchangeCode(discovery, {
    clientId: config.clientId,
    code: params.get('code'),
    redirectUri: config.redirectUri,
    verifier: stash.verifier,
  });
  if (tokenRes.status !== 200) {
    showFailure(mapTokenError(tokenRes.body?.error));
    return;
  }

  let jwks;
  try {
    const jwksRes = await fetch(discovery.jwks_uri);
    jwks = await jwksRes.json();
  } catch (err) {
    showFailure(`Could not fetch the signing keys: ${err.message}`);
    return;
  }

  let claims;
  try {
    claims = await verifyIdToken(tokenRes.body.id_token, {
      jwks,
      issuer: config.issuer,
      clientId: config.clientId,
      nonce: stash.nonce,
    });
  } catch (err) {
    showFailure(`Sign-in could not be verified: ${err.message}`);
    return;
  }

  sessionStorage.removeItem(STASH_KEY);
  history.replaceState(null, '', location.pathname);

  // window.open() names the popup's browsing context; a page that never
  // had a popup opener falls back to that name check, so this is accurate
  // even when Cross-Origin-Opener-Policy on the issuer's pages detached
  // window.opener.
  const wasPopup = Boolean(window.opener) || window.name === 'login-with-rezen';

  const result = {
    type: 'login-with-rezen',
    access_token: tokenRes.body.access_token,
    expires_in: tokenRes.body.expires_in,
    scope: tokenRes.body.scope,
    refresh_token: tokenRes.body.refresh_token,
    claims,
    steps: [
      wasPopup ? 'Popup opened and completed sign-in' : 'Redirect fallback used (popup blocked)',
      'Code exchanged (public client, PKCE only)',
      'ID token verified (RS256, nonce checked)',
    ],
  };

  // Deliver over BroadcastChannel — it works even when the issuer's pages
  // set Cross-Origin-Opener-Policy, which can detach window.opener — and
  // also over postMessage when an opener is present, belt and braces.
  new BroadcastChannel(CHANNEL_NAME).postMessage(result);
  if (window.opener) {
    window.opener.postMessage(result, location.origin);
  }

  if (wasPopup) {
    showMessage('Signed in — you can close this window.');
    window.close();
    return;
  }

  // Redirect fallback: there is no opener to hand the result to. Stash the
  // access token, expiry, scope, and claims — never the refresh token —
  // and let app.js finish the pipeline (userinfo, /me) after the reload.
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    accessToken: result.access_token,
    expiresAt: Date.now() + (result.expires_in || 0) * 1000,
    scope: result.scope,
    claims: result.claims,
    steps: result.steps,
    completed: false,
  }));
  location.replace('/');
}

run();
