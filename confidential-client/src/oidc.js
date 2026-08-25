import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto';

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

// PKCE (S256): a random verifier, and the challenge that goes on the wire.
export function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
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

// RFC 6749 §2.3.1: client_id and client_secret are each form-urlencoded
// before the ':' join and base64 — a secret containing ':', '%', or '+'
// otherwise misparses at the token endpoint.
function formEncode(value) {
  return encodeURIComponent(value).replace(/%20/g, '+');
}

// Confidential clients authenticate with Basic auth; public clients (empty
// clientSecret) send client_id in the body instead — PKCE and the single-use
// code carry the security for them.
export async function exchangeCode(discovery, { clientId, clientSecret, code, redirectUri, verifier }) {
  const form = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  };
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (clientSecret) {
    const credentials = `${formEncode(clientId)}:${formEncode(clientSecret)}`;
    headers.Authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
  } else {
    form.client_id = clientId;
  }
  const res = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers,
    body: new URLSearchParams(form).toString(),
  });
  // A non-JSON body (an HTML error page, say) becomes {} — callers decide on the status code.
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

// Verifies signature (RS256 only — the header never chooses the algorithm),
// issuer, audience, expiry, and nonce. Throws a descriptive error on any
// failure; returns the claims only once everything checks out.
//
// The browser sample has the same function written against the Web Crypto
// API — public-client/public/oidc.js. The two are deliberately identical in
// what they accept, what they reject, and what they say when they reject;
// ../../test-vectors/id-token.json is the shared vector both test suites run
// through their own copy. Change one and you must change the other, or that
// vector fails in the suite you didn't touch.
export async function verifyIdToken(idToken, { jwks, issuer, clientId, nonce }) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) throw new Error('id_token is not a JWT');
  const [h, p, s] = parts;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  if (header.alg !== 'RS256') throw new Error(`id_token alg must be RS256, got ${header.alg}`);

  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no signing key found for kid ${header.kid}`);
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const ok = cryptoVerify('RSA-SHA256', Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('id_token signature is invalid');

  const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
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

// Revocation (RFC 7009) — what "disconnect this app" means on the wire.
// Revoking a refresh token revokes its whole family AND the API keys minted
// under it; revoking an access token revokes that key alone. The user's
// stored consent survives either way, so a later sign-in reconnects without
// a new consent screen.
//
// The endpoint comes from discovery like every other one. The token goes in
// the form body — never in the URL, never in a log line. Authentication is
// the same as at the token endpoint: Basic for a confidential client,
// client_id in the body for a public one.
//
// RFC 7009 §2.2: the endpoint answers 200 for an unknown, expired, or
// foreign token as readily as for a live one — revocation is idempotent and
// must not become an oracle for whether a token is valid. So 200 means
// "revocation was accepted", not "that token existed".
export async function revoke(discovery, { clientId, clientSecret, token, tokenTypeHint }) {
  if (!discovery.revocation_endpoint) {
    throw new Error('the issuer does not publish a revocation_endpoint');
  }
  const form = { token };
  if (tokenTypeHint) form.token_type_hint = tokenTypeHint;
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (clientSecret) {
    const credentials = `${formEncode(clientId)}:${formEncode(clientSecret)}`;
    headers.Authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
  } else {
    form.client_id = clientId;
  }
  const res = await fetch(discovery.revocation_endpoint, {
    method: 'POST',
    headers,
    body: new URLSearchParams(form).toString(),
  });
  return { status: res.status };
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
