// The redirect target for /authorize. Runs in the popup window, or in the
// main tab when the popup was blocked and app.js fell back to a full-page
// redirect — the code below handles both the same way.
import { discover, exchangeCode, verifyIdToken } from './oidc.js';
import { CHANNEL_NAME, SESSION_KEY, STASH_KEY } from './keys.js';

// How long the popup waits for the opener to acknowledge the result before
// closing itself anyway.
const ACK_TIMEOUT_MS = 1500;

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
  let config;
  try {
    config = (await import('/config.js')).default;
  } catch (err) {
    showFailure(`Could not load the app configuration: ${err.message}`);
    return;
  }
  const params = new URLSearchParams(location.search);

  // state is checked before anything else in the query string is trusted —
  // including error — so a crafted /callback?error=... link can't show this
  // tab the issuer's error page for a sign-in it never started.
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

  const errParam = params.get('error');
  if (errParam) {
    showFailure(mapAuthorizeError(errParam, params.get('error_description')));
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
    if (!jwksRes.ok) {
      showFailure(`Could not fetch the signing keys (HTTP ${jwksRes.status})`);
      return;
    }
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

  // Cross-Origin-Opener-Policy: same-origin on the issuer's pages detaches
  // window.opener when the popup navigates there, and can clear window.name
  // along with it — neither is reliable evidence of how this flow started.
  // app.js stashes popup: true (or false, in the popup-blocked fallback)
  // before it ever navigates anywhere, so read it from there instead.
  const wasPopup = stash.popup === true;

  // RFC 6749 §5.1: scope is OPTIONAL in the token response when it equals
  // the request — a compliant server may omit it entirely.
  const result = {
    type: 'login-with-rezen',
    state: stash.state,
    access_token: tokenRes.body.access_token,
    expires_in: tokenRes.body.expires_in,
    scope: tokenRes.body.scope || config.scopes.join(' '),
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
  // also over postMessage when an opener is present, belt and braces. The
  // result carries this flow's state so the opener applies it only to the
  // tab that started it.
  const resultChannel = new BroadcastChannel(CHANNEL_NAME);
  resultChannel.postMessage(result);
  if (window.opener) {
    window.opener.postMessage(result, location.origin);
  }

  if (wasPopup) {
    // Wait briefly for the opener to acknowledge it received the result
    // before closing — closing immediately risks the opener never applying
    // it (a reload at the wrong instant, say).
    showMessage('Finishing up…');
    let settled = false;
    const finish = (text) => {
      if (settled) return;
      settled = true;
      showMessage(text);
      resultChannel.close();
      window.close();
    };
    const timer = setTimeout(() => finish('Signed in — return to the app window.'), ACK_TIMEOUT_MS);
    resultChannel.onmessage = (event) => {
      const ack = event.data;
      if (ack && ack.type === 'login-with-rezen:ack' && ack.state === result.state) {
        clearTimeout(timer);
        finish('Signed in — you can close this window.');
      }
    };
    return;
  }

  // Redirect fallback: there is no opener to hand the result to. Stash the
  // access token, expiry, scope, and claims — never the refresh token —
  // and let app.js finish the pipeline (userinfo, /me) after the reload.
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    accessToken: result.access_token,
    // A missing expires_in means "no expiry known", not "expired now".
    expiresAt: typeof result.expires_in === 'number' ? Date.now() + result.expires_in * 1000 : undefined,
    scope: result.scope,
    claims: result.claims,
    steps: result.steps,
    completed: false,
  }));
  location.replace('/');
}

run();
