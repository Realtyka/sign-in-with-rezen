// Protocol module for the public client. Plain browser ES module — no
// Node imports — so it runs unmodified both in the page and under the
// Node test (Node's Web Crypto API is the same interface).

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function base64UrlToBytes(value) {
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded.replaceAll('-', '+').replaceAll('_', '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlToJson(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value)));
}

// Reads the endpoint list from the issuer's discovery document — nothing
// below hardcodes an endpoint path.
export async function discover(issuer) {
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`discovery failed: HTTP ${res.status}`);
  const doc = await res.json();
  // OIDC Discovery 4.3 (MUST): the issuer in the document must exactly
  // match the issuer this was requested from.
  if (doc.issuer !== issuer) throw new Error('discovery issuer mismatch');
  return doc;
}

// A random URL-safe token — used for state and nonce.
export function randomToken(byteLength = 16) {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

// PKCE (S256): a random verifier, and the challenge that goes on the wire.
export async function pkce() {
  const verifier = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = bytesToBase64Url(new Uint8Array(digest));
  return { verifier, challenge };
}

export function authorizeUrl(discovery, { clientId, redirectUri, scopes, state, nonce, challenge }) {
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.href;
}

// Public client: client_id travels in the body, never a secret, never an
// Authorization header. PKCE and the single-use code carry the security.
export async function exchangeCode(discovery, { clientId, code, redirectUri, verifier }) {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  const res = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  // A non-JSON body (an HTML error page, say) becomes {} — callers decide on the status code.
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

// Verifies signature (RS256 only — the header never chooses the algorithm),
// issuer, audience, expiry, and nonce. Throws a descriptive error on any
// failure; returns the claims only once everything checks out.
export async function verifyIdToken(idToken, { jwks, issuer, clientId, nonce }) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) throw new Error('id_token is not a JWT');
  const [h, p, s] = parts;
  const header = base64UrlToJson(h);
  if (header.alg !== 'RS256') throw new Error(`id_token alg must be RS256, got ${header.alg}`);

  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no signing key found for kid ${header.kid}`);
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const signedData = new TextEncoder().encode(`${h}.${p}`);
  const signatureOk = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, base64UrlToBytes(s), signedData);
  if (!signatureOk) throw new Error('id_token signature is invalid');

  const claims = base64UrlToJson(p);
  if (claims.iss !== issuer) throw new Error(`id_token iss mismatch: ${claims.iss}`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) throw new Error('id_token aud does not include this client');
  // OIDC Core 3.1.3.7: with more than one aud value, azp must name this client.
  if (aud.length > 1 && claims.azp !== clientId) {
    throw new Error('id_token azp must equal this client when aud has more than one value');
  }
  // Whenever azp is present at all, it must equal this client.
  if (claims.azp !== undefined && claims.azp !== clientId) {
    throw new Error('id_token azp must equal this client when present');
  }

  const now = Math.floor(Date.now() / 1000);
  const CLOCK_SKEW_LEEWAY_SECONDS = 60;
  if (typeof claims.exp !== 'number' || claims.exp <= now - CLOCK_SKEW_LEEWAY_SECONDS) {
    throw new Error('id_token has expired');
  }
  if (typeof claims.iat !== 'number' || claims.iat > now + CLOCK_SKEW_LEEWAY_SECONDS) {
    throw new Error('id_token iat is missing or in the future');
  }
  if (claims.nonce !== nonce) throw new Error('id_token nonce does not match');

  return claims;
}

// The one place a Bearer token is used — /userinfo is the OIDC exception.
export async function userinfo(discovery, accessToken) {
  const res = await fetch(discovery.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  // A non-JSON body (an HTML error page, say) becomes {} — callers decide on the status code.
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

// Real resource APIs take the access token as an API key, never Bearer.
export async function apiCall(apiBase, path, accessToken) {
  const res = await fetch(`${apiBase}${path}`, {
    headers: { 'x-api-key': accessToken, Accept: 'application/json' },
  });
  // A non-JSON body (an HTML error page, say) becomes {} — callers decide on the status code.
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}
