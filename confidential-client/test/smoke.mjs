// Offline smoke test — no network beyond 127.0.0.1. Stands up a stub OIDC
// issuer and a stub Real API, boots the sample against them, and drives the
// full sign-in flow (and its failure modes) with fetch.
import assert from 'node:assert';
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import http from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadConfig } from '../src/config.js';
import { createServer } from '../src/server.js';
import { discover, verifyIdToken } from '../src/oidc.js';

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signRS256(privateKey, header, payload) {
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(payload));
  const signature = cryptoSign('RSA-SHA256', Buffer.from(`${h}.${p}`), privateKey);
  return `${h}.${p}.${base64url(signature)}`;
}

function signHS256(secret, header, payload) {
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(payload));
  const signature = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${base64url(signature)}`;
}

const TEST_USER = {
  sub: 'user-test-0001',
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  yentaId: 'yenta-test-0001',
};
const TEST_PROFILE = { displayName: 'Ada Lovelace', type: 'AGENT' };

// A stub issuer + a stub resource API, both on 127.0.0.1. tokenMode lets a
// test flip the id_token's shape (bad alg / bad nonce) for exactly one
// exchange without any extra wiring in the sample itself.
async function startStub({ clientId, clientSecret }) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  // A second key pair that is never published in the JWKS — the 'wrong-key'
  // mode signs a perfectly well-formed RS256 token with it, so nothing
  // before the signature check has anything to object to.
  const { privateKey: unpublishedKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'test-key-1';
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };

  const issuerPort = await getFreePort();
  const issuerUrl = `http://127.0.0.1:${issuerPort}`;
  const apiPort = await getFreePort();
  const apiUrl = `http://127.0.0.1:${apiPort}`;

  const codes = new Map(); // code -> { codeChallenge, redirectUri, nonce, scope }
  const accessTokens = new Set();
  const refreshTokens = new Set();
  const revocations = [];
  let tokenMode = 'ok';
  let revokeMode = 'ok';
  let userinfoMode = 'ok';
  let discoveryMode = 'ok';

  function json(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  }

  const issuerServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, issuerUrl);

    if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, {
        issuer: discoveryMode === 'bad-issuer' ? `${issuerUrl}/not-the-issuer` : issuerUrl,
        authorization_endpoint: `${issuerUrl}/authorize`,
        token_endpoint: `${issuerUrl}/token`,
        userinfo_endpoint: `${issuerUrl}/userinfo`,
        revocation_endpoint: `${issuerUrl}/revoke`,
        jwks_uri: `${issuerUrl}/jwks`,
      });
    }

    if (req.method === 'GET' && url.pathname === '/jwks') {
      return json(res, 200, { keys: [jwk] });
    }

    if (req.method === 'GET' && url.pathname === '/authorize') {
      const q = url.searchParams;
      assert.equal(q.get('response_type'), 'code');
      assert.equal(q.get('code_challenge_method'), 'S256');
      assert.equal(q.get('client_id'), clientId);
      assert.ok(q.get('state'), 'authorize request must carry state');
      assert.ok(q.get('nonce'), 'authorize request must carry nonce');
      assert.ok(q.get('code_challenge'), 'authorize request must carry a code_challenge');

      const code = randomBytes(16).toString('hex');
      codes.set(code, {
        codeChallenge: q.get('code_challenge'),
        redirectUri: q.get('redirect_uri'),
        nonce: q.get('nonce'),
        scope: q.get('scope'),
      });
      const target = new URL(q.get('redirect_uri'));
      target.searchParams.set('code', code);
      target.searchParams.set('state', q.get('state'));
      target.searchParams.set('iss', issuerUrl);
      res.writeHead(302, { Location: target.href });
      return res.end();
    }

    if (req.method === 'POST' && url.pathname === '/token') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      assert.equal(form.get('grant_type'), 'authorization_code');

      const code = form.get('code');
      const entry = codes.get(code);
      if (!entry) return json(res, 400, { error: 'invalid_grant' });

      const challenge = createHash('sha256').update(form.get('code_verifier') || '').digest('base64url');
      if (challenge !== entry.codeChallenge) return json(res, 400, { error: 'invalid_grant' });
      if (form.get('redirect_uri') !== entry.redirectUri) return json(res, 400, { error: 'invalid_grant' });

      const authHeader = req.headers.authorization;
      if (clientSecret) {
        assert.ok(authHeader && authHeader.startsWith('Basic '), 'confidential exchange must send Basic auth');
        const decoded = Buffer.from(authHeader.slice('Basic '.length), 'base64').toString();
        // RFC 6749 §2.3.1: client_id and client_secret are each
        // form-urlencoded before the ':' join — decode the same way, split
        // on the FIRST ':' only (the secret itself may contain one).
        const sep = decoded.indexOf(':');
        const decodedId = decodeURIComponent(decoded.slice(0, sep).replace(/\+/g, ' '));
        const decodedSecret = decodeURIComponent(decoded.slice(sep + 1).replace(/\+/g, ' '));
        assert.equal(decodedId, clientId, 'Basic auth must carry the client_id, form-decoded');
        assert.equal(decodedSecret, clientSecret, 'Basic auth must carry the client_secret, form-decoded');
        assert.equal(form.get('client_id'), null, 'confidential exchange must not also send client_id in the body');
      } else {
        assert.equal(authHeader, undefined, 'public exchange must not send an Authorization header');
        assert.equal(form.get('client_id'), clientId, 'public exchange must send client_id in the body');
      }

      codes.delete(code);
      const accessToken = `real_test_${randomBytes(8).toString('hex')}`;
      accessTokens.add(accessToken);
      const now = Math.floor(Date.now() / 1000);
      const multiAud = tokenMode === 'multi-aud-ok' || tokenMode === 'multi-aud-no-azp';
      const claims = {
        iss: tokenMode === 'bad-iss' ? `${issuerUrl}/not-the-issuer` : issuerUrl,
        aud: tokenMode === 'bad-aud' ? 'someone-elses-client' : multiAud ? [clientId, 'other-client'] : clientId,
        sub: TEST_USER.sub,
        exp: tokenMode === 'expired' ? now - 3600 : tokenMode === 'exp-leeway' ? now - 30 : now + 3600,
        iat: tokenMode === 'future-iat' ? now + 3600 : now,
        nonce: tokenMode === 'bad-nonce' ? 'not-the-right-nonce' : entry.nonce,
        name: TEST_USER.name,
        email: TEST_USER.email,
        yentaId: TEST_USER.yentaId,
      };
      if (tokenMode === 'multi-aud-ok') claims.azp = clientId;
      const idToken = tokenMode === 'bad-alg'
        ? signHS256('not-a-real-secret', { alg: 'HS256', typ: 'JWT' }, claims)
        : signRS256(tokenMode === 'wrong-key' ? unpublishedKey : privateKey, { alg: 'RS256', typ: 'JWT', kid }, claims);

      const refreshToken = `rt_test_${randomBytes(8).toString('hex')}`;
      refreshTokens.add(refreshToken);
      return json(res, 200, {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 43200,
        scope: tokenMode === 'no-scope' ? undefined : entry.scope,
        refresh_token: refreshToken,
        id_token: idToken,
      });
    }

    // RFC 7009 revocation. Records every call so a test can assert what the
    // sample sent, and checks the client authenticated the way its client
    // type requires — Basic for a confidential client, client_id in the body
    // for a public one.
    if (req.method === 'POST' && url.pathname === '/revoke') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const authHeader = req.headers.authorization;
      if (clientSecret) {
        assert.ok(authHeader && authHeader.startsWith('Basic '), 'a confidential revoke must send Basic auth');
        const decoded = Buffer.from(authHeader.slice('Basic '.length), 'base64').toString();
        const sep = decoded.indexOf(':');
        assert.equal(decodeURIComponent(decoded.slice(0, sep).replace(/\+/g, ' ')), clientId);
        assert.equal(decodeURIComponent(decoded.slice(sep + 1).replace(/\+/g, ' ')), clientSecret);
        assert.equal(form.get('client_id'), null, 'a confidential revoke must not also send client_id in the body');
      } else {
        assert.equal(authHeader, undefined, 'a public revoke must not send an Authorization header');
        assert.equal(form.get('client_id'), clientId, 'a public revoke must send client_id in the body');
        assert.equal(form.get('client_secret'), null, 'a public client has no secret to send');
      }
      const token = form.get('token');
      assert.ok(token, '/revoke must be given a token');
      const hint = form.get('token_type_hint');
      assert.ok(hint === 'access_token' || hint === 'refresh_token', `/revoke token_type_hint should name a token type, got ${hint}`);
      revocations.push({ token, hint });
      if (revokeMode === 'unavailable') return json(res, 503, { error: 'temporarily_unavailable' });
      // The cascade the guide describes: a refresh token takes its family
      // and the keys minted under it; an access token takes that key alone.
      if (refreshTokens.delete(token)) accessTokens.clear();
      else accessTokens.delete(token);
      res.writeHead(200);
      return res.end();
    }

    if (req.method === 'GET' && url.pathname === '/userinfo') {
      const auth = req.headers.authorization;
      const token = auth && auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : undefined;
      if (!token || !accessTokens.has(token)) return json(res, 401, { error: 'invalid_token' });
      return json(res, 200, {
        sub: userinfoMode === 'bad-sub' ? 'someone-elses-sub' : TEST_USER.sub,
        name: TEST_USER.name,
        email: TEST_USER.email,
        email_verified: true,
        yentaId: TEST_USER.yentaId,
      });
    }

    return json(res, 404, { error: 'not_found' });
  });
  await new Promise((resolve) => issuerServer.listen(issuerPort, '127.0.0.1', resolve));

  const apiServer = http.createServer((req, res) => {
    const url = new URL(req.url, apiUrl);
    if (req.method === 'GET' && url.pathname === '/api/v1/users/me') {
      assert.equal(req.headers.authorization, undefined, 'the API call must never send Authorization');
      const key = req.headers['x-api-key'];
      if (!key || !accessTokens.has(key)) return json(res, 401, { error: 'invalid_key' });
      return json(res, 200, TEST_PROFILE);
    }
    return json(res, 404, { error: 'not_found' });
  });
  await new Promise((resolve) => apiServer.listen(apiPort, '127.0.0.1', resolve));

  return {
    issuerUrl,
    apiUrl,
    setTokenMode(mode) { tokenMode = mode; },
    setUserinfoMode(mode) { userinfoMode = mode; },
    setDiscoveryMode(mode) { discoveryMode = mode; },
    setRevokeMode(mode) { revokeMode = mode; },
    revocations,
    accessTokens,
    close() {
      return Promise.all([
        new Promise((resolve) => issuerServer.close(resolve)),
        new Promise((resolve) => apiServer.close(resolve)),
      ]);
    },
  };
}

function extractCookie(res) {
  const setCookie = res.headers.get('set-cookie');
  return setCookie ? setCookie.split(';')[0] : undefined;
}

let checks = 0;
function ok(label) {
  checks += 1;
  console.log(`ok - ${label}`);
}

async function runFlow(label, { clientSecret }) {
  const clientId = `client-${label}`;
  const stub = await startStub({ clientId, clientSecret });
  const samplePort = await getFreePort();

  const scratch = mkdtempSync(join(tmpdir(), 'login-with-rezen-'));
  const envPath = join(scratch, `${label}.env`);
  writeFileSync(envPath, [
    `ISSUER=${stub.issuerUrl}`,
    `CLIENT_ID=${clientId}`,
    `CLIENT_SECRET=${clientSecret}`,
    `REDIRECT_URI=http://127.0.0.1:${samplePort}/callback`,
    'SCOPES=openid profile email real.identity ACCOUNT_READ',
    `PORT=${samplePort}`,
    `API_BASE=${stub.apiUrl}`,
    '',
  ].join('\n'));

  process.env.LOGIN_WITH_REZEN_ENV = envPath;
  const config = loadConfig();
  assert.equal(config.issuer, stub.issuerUrl);
  assert.equal(config.apiBase, stub.apiUrl);
  assert.equal(config.clientSecret, clientSecret);

  const server = createServer(config);
  await new Promise((resolve) => server.listen(samplePort, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${samplePort}`;

  // 1. GET / shows the button before sign-in.
  const homeRes = await fetch(base + '/');
  const homeHtml = await homeRes.text();
  assert.ok(homeHtml.includes('Sign in with reZEN'), `${label}: home page should show the button`);
  ok(`${label}: GET / shows the Sign in with reZEN button`);

  assert.equal(homeRes.headers.get('x-content-type-options'), 'nosniff', `${label}: GET / should send X-Content-Type-Options: nosniff`);
  assert.equal(homeRes.headers.get('x-frame-options'), 'DENY', `${label}: GET / should send X-Frame-Options: DENY`);
  assert.ok(homeRes.headers.get('content-security-policy'), `${label}: GET / should send a Content-Security-Policy header`);
  ok(`${label}: GET / sends security headers`);

  stub.setDiscoveryMode('bad-issuer');
  await assert.rejects(
    () => discover(stub.issuerUrl),
    undefined,
    `${label}: discover() should reject a discovery document whose issuer does not match the requested issuer`,
  );
  stub.setDiscoveryMode('ok');
  ok(`${label}: discover() rejects a discovery document whose issuer does not match the requested issuer`);

  // Drives one authorize -> callback round trip from a fresh session; returns
  // the cookie the callback should be called with and the callback URL the
  // stub redirected to.
  async function beginFlow() {
    const preRes = await fetch(base + '/');
    let cookie = extractCookie(preRes);
    const loginRes = await fetch(base + '/sign-in', { redirect: 'manual', headers: cookie ? { cookie } : {} });
    assert.equal(loginRes.status, 302, `${label}: /sign-in should redirect`);
    cookie = extractCookie(loginRes) || cookie;
    const authorizeLocation = new URL(loginRes.headers.get('location'));
    assert.equal(authorizeLocation.origin, stub.issuerUrl, `${label}: /sign-in should redirect to the issuer`);
    assert.equal(authorizeLocation.searchParams.get('response_type'), 'code');
    assert.equal(authorizeLocation.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(authorizeLocation.searchParams.get('state'));
    assert.ok(authorizeLocation.searchParams.get('nonce'));

    const authorizeRes = await fetch(authorizeLocation.href, { redirect: 'manual' });
    assert.equal(authorizeRes.status, 302);
    const callbackLocation = new URL(authorizeRes.headers.get('location'));
    assert.equal(callbackLocation.pathname, '/callback');
    assert.ok(callbackLocation.searchParams.get('code'));
    assert.equal(callbackLocation.searchParams.get('iss'), stub.issuerUrl);
    return { cookie, callbackLocation };
  }

  // 2 & 3. /sign-in -> authorize (PKCE S256, state, nonce), follow through to /callback.
  const { cookie, callbackLocation } = await beginFlow();
  ok(`${label}: /sign-in redirects to authorize with PKCE S256, state, and nonce`);

  const callbackRes = await fetch(callbackLocation.href, { redirect: 'manual', headers: { cookie } });
  assert.equal(callbackRes.status, 302, `${label}: a valid callback should redirect home`);
  const signedInCookie = extractCookie(callbackRes) || cookie;
  ok(`${label}: /callback exchanges the code and redirects to /`);

  // 5. GET / shows identity, granted scope, and profile — no token leaked.
  const finalRes = await fetch(base + '/', { headers: { cookie: signedInCookie } });
  const finalHtml = await finalRes.text();
  assert.ok(finalHtml.includes(TEST_USER.sub), `${label}: page should show sub`);
  assert.ok(finalHtml.includes(TEST_USER.name), `${label}: page should show name`);
  assert.ok(finalHtml.includes(TEST_USER.email), `${label}: page should show email`);
  assert.ok(finalHtml.includes(TEST_USER.yentaId), `${label}: page should show yentaId`);
  assert.ok(finalHtml.includes('openid'), `${label}: page should show the granted scope`);
  assert.ok(finalHtml.includes(TEST_PROFILE.displayName), `${label}: page should show the profile displayName`);
  assert.ok(!finalHtml.includes('real_test'), `${label}: page must never contain the access token`);
  assert.ok(!finalHtml.includes('id_token'), `${label}: page must never mention the raw id_token`);
  ok(`${label}: GET / shows identity, granted scope, and profile with no token leaked`);

  // Negative: wrong state is rejected.
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const tampered = new URL(cb.href);
    tampered.searchParams.set('state', 'not-the-right-state');
    const res = await fetch(tampered.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: wrong state should be rejected`);
    const html = await res.text();
    assert.ok(!html.includes(TEST_USER.sub), `${label}: a rejected callback must not sign in`);
  }
  ok(`${label}: callback rejects a state mismatch`);

  // Negative: wrong iss is rejected.
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const tampered = new URL(cb.href);
    tampered.searchParams.set('iss', 'http://127.0.0.1:1/not-the-issuer');
    const res = await fetch(tampered.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: wrong iss should be rejected`);
  }
  ok(`${label}: callback rejects an iss mismatch`);

  // Negative: an id_token signed with alg other than RS256 is rejected.
  stub.setTokenMode('bad-alg');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: an HS256 id_token should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects an id_token whose alg is not RS256`);

  // Negative: an id_token whose SIGNED iss claim names a different issuer is
  // rejected. The callback-query iss check above is a separate control — it
  // guards the redirect, this one guards the token.
  stub.setTokenMode('bad-iss');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: an id_token whose iss claim is wrong should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects an id_token whose signed iss claim does not match the issuer`);

  // Negative: a well-formed RS256 id_token signed with a key that is not in
  // the JWKS. Everything before the signature check passes, so this is the
  // case that proves the signature is actually verified.
  stub.setTokenMode('wrong-key');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: an RS256 id_token signed with an unpublished key should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects a valid RS256 id_token signed with the wrong key`);

  // Negative: a nonce mismatch is rejected.
  stub.setTokenMode('bad-nonce');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: a nonce mismatch should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects a nonce mismatch`);

  // Negative: an expired id_token is rejected.
  stub.setTokenMode('expired');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: an expired id_token should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects an expired id_token`);

  // Negative: an aud mismatch is rejected.
  stub.setTokenMode('bad-aud');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: an aud mismatch should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects an aud mismatch`);

  // Negative: multiple aud values without azp naming this client is rejected.
  stub.setTokenMode('multi-aud-no-azp');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: a multi-value aud without a matching azp should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects a multi-value aud without a matching azp`);

  // Positive: multiple aud values with azp naming this client is accepted.
  stub.setTokenMode('multi-aud-ok');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    assert.equal(res.status, 302, `${label}: a multi-value aud with a matching azp should still sign in`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback accepts a multi-value aud whose azp names this client`);

  // Negative: an id_token issued in the future is rejected.
  stub.setTokenMode('future-iat');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: an id_token with a future iat should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects an id_token whose iat is in the future`);

  // Positive: an id_token that expired within the clock-skew leeway is accepted.
  stub.setTokenMode('exp-leeway');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    assert.equal(res.status, 302, `${label}: an id_token within the clock-skew leeway should still sign in`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback accepts an id_token that expired within the clock-skew leeway`);

  // A token response that omits scope falls back to the requested scopes.
  stub.setTokenMode('no-scope');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    assert.equal(res.status, 302, `${label}: a token response without scope should still sign in`);
    const signedIn = extractCookie(res) || c;
    const page = await fetch(base + '/', { headers: { cookie: signedIn } });
    const html = await page.text();
    for (const s of config.scopes) {
      assert.ok(html.includes(s), `${label}: a token response without scope should fall back to the requested scopes (missing ${s})`);
    }
  }
  stub.setTokenMode('ok');
  ok(`${label}: a token response without scope falls back to the requested scopes`);

  // A callback that fails still spends the flow: replaying the same state at
  // the same session must not be accepted a second time.
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const tampered = new URL(cb.href);
    tampered.searchParams.set('iss', 'http://127.0.0.1:1/not-the-issuer');
    const first = await fetch(tampered.href, { headers: { cookie: c } });
    assert.equal(first.status, 400, `${label}: the tampered callback should fail`);
    const replay = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(replay.status, 400, `${label}: replaying the same state after a failed callback should be refused`);
    const html = await replay.text();
    assert.ok(html.includes('state parameter did not match'), `${label}: the replay should be refused on state, not signed in`);
  }
  ok(`${label}: a failed callback spends its state — the same state cannot be replayed`);

  // A userinfo sub mismatch is ignored — the page keeps the id_token identity.
  stub.setUserinfoMode('bad-sub');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    assert.equal(res.status, 302, `${label}: a userinfo sub mismatch should still sign in`);
    const signedIn = extractCookie(res) || c;
    const page = await fetch(base + '/', { headers: { cookie: signedIn } });
    const html = await page.text();
    assert.ok(html.includes(TEST_USER.sub), `${label}: a userinfo sub mismatch should keep the id_token sub`);
    assert.ok(html.includes('Userinfo ignored'), `${label}: a userinfo sub mismatch should be recorded as a step`);
  }
  stub.setUserinfoMode('ok');
  ok(`${label}: a userinfo sub mismatch keeps the id_token identity`);

  // Sign out and disconnect are POST, same-origin only.
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const done = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    const signedIn = extractCookie(done) || c;

    for (const path of ['/sign-out', '/disconnect']) {
      const getRes = await fetch(base + path, { redirect: 'manual', headers: { cookie: signedIn } });
      assert.equal(getRes.status, 405, `${label}: GET ${path} should be refused`);
      assert.equal(getRes.headers.get('allow'), 'POST', `${label}: GET ${path} should say which method to use`);

      const crossSite = await fetch(base + path, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: signedIn, 'sec-fetch-site': 'cross-site' },
      });
      assert.equal(crossSite.status, 403, `${label}: a cross-site POST to ${path} should be refused`);
    }

    // Still signed in — neither refused request did anything.
    const still = await fetch(base + '/', { headers: { cookie: signedIn } });
    assert.ok((await still.text()).includes(TEST_USER.sub), `${label}: a refused request must not end the session`);
  }
  ok(`${label}: /sign-out and /disconnect refuse GET (405) and cross-site POST (403)`);

  // Sign out is local: the session goes, and nothing is sent to the issuer.
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const done = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    const signedIn = extractCookie(done) || c;
    const before = stub.revocations.length;

    const res = await fetch(base + '/sign-out', {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: signedIn, 'sec-fetch-site': 'same-origin' },
    });
    assert.equal(res.status, 302, `${label}: a same-origin POST to /sign-out should redirect home`);
    assert.equal(stub.revocations.length, before, `${label}: sign out must not call /revoke`);
    const page = await fetch(base + '/', { headers: { cookie: signedIn } });
    const html = await page.text();
    assert.ok(!html.includes(TEST_USER.sub), `${label}: sign out should end the session`);
    assert.ok(!html.includes('Disconnected'), `${label}: sign out is not a disconnect`);
  }
  ok(`${label}: POST /sign-out ends the session locally and never calls /revoke`);

  // Disconnect revokes the refresh token — the family, and the keys minted
  // under it — and then ends the session.
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const done = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    const signedIn = extractCookie(done) || c;
    const before = stub.revocations.length;

    const res = await fetch(base + '/disconnect', {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: signedIn, 'sec-fetch-site': 'same-origin' },
    });
    assert.equal(res.status, 302, `${label}: a same-origin POST to /disconnect should redirect home`);
    assert.equal(res.headers.get('location'), '/?disconnected=ok', `${label}: a successful disconnect should say so on the landing`);
    assert.equal(stub.revocations.length, before + 1, `${label}: disconnect should call /revoke exactly once`);
    const call = stub.revocations.at(-1);
    assert.equal(call.hint, 'refresh_token', `${label}: disconnect should revoke the refresh token`);
    assert.ok(call.token.startsWith('rt_test_'), `${label}: disconnect should send the refresh token, not the access token`);
    assert.equal(stub.accessTokens.size, 0, `${label}: revoking the refresh token should take the keys minted under it`);

    const page = await fetch(base + '/?disconnected=ok', { headers: { cookie: signedIn } });
    const html = await page.text();
    assert.ok(!html.includes(TEST_USER.sub), `${label}: disconnect should end the session`);
    assert.ok(html.includes('Disconnected'), `${label}: the landing should confirm the disconnect`);
    assert.ok(!html.includes('rt_test'), `${label}: the page must never contain a token`);
  }
  ok(`${label}: POST /disconnect revokes the refresh token, then ends the session`);

  // A revoke that fails still ends the local session, and says it failed.
  stub.setRevokeMode('unavailable');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const done = await fetch(cb.href, { redirect: 'manual', headers: { cookie: c } });
    const signedIn = extractCookie(done) || c;

    const res = await fetch(base + '/disconnect', {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: signedIn, 'sec-fetch-site': 'same-origin' },
    });
    assert.equal(res.headers.get('location'), '/?disconnected=failed', `${label}: a failed revoke should be reported`);
    const page = await fetch(base + '/?disconnected=failed', { headers: { cookie: signedIn } });
    const html = await page.text();
    assert.ok(!html.includes(TEST_USER.sub), `${label}: a failed revoke must still end the local session`);
    assert.ok(html.includes('could not be reached'), `${label}: the landing should say the revoke did not succeed`);
  }
  stub.setRevokeMode('ok');
  ok(`${label}: a failed revoke still ends the session and reports the failure`);

  await new Promise((resolve) => server.close(resolve));
  await stub.close();
}

// The shared id_token test vector — the same bytes the browser sample's
// suite runs through its own verifyIdToken. See test-vectors/id-token.json.
async function testSharedVector() {
  const vectorPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-vectors', 'id-token.json');
  const vector = JSON.parse(readFileSync(vectorPath, 'utf8'));
  const options = {
    jwks: vector.jwks,
    issuer: vector.params.issuer,
    clientId: vector.params.clientId,
    nonce: vector.params.nonce,
  };

  const claims = await verifyIdToken(vector.valid.idToken, options);
  assert.deepEqual(claims, vector.valid.claims, 'the shared vector\'s valid id_token should verify to its recorded claims');
  ok(`shared vector: ${vector.valid.name}`);

  for (const bad of vector.invalid) {
    await assert.rejects(
      () => verifyIdToken(bad.idToken, options),
      (err) => {
        assert.ok(
          err.message.includes(bad.expect),
          `shared vector: rejecting "${bad.name}" should say "${bad.expect}", got "${err.message}"`,
        );
        return true;
      },
      `shared vector: ${bad.name} should be rejected`,
    );
    ok(`shared vector rejects: ${bad.name}`);
  }
}

// Reserved characters (':', '%', '+', ' ') exercise the RFC 6749 §2.3.1
// form-encoding round trip — the env parser trims only line ends, so none
// of these need escaping in the .env file itself.
// A PORT that is not a port falls back to the default with a note, rather
// than failing deep inside listen() with an opaque socket error.
function testBadPort() {
  const scratch = mkdtempSync(join(tmpdir(), 'login-with-rezen-port-'));
  const envPath = join(scratch, 'bad-port.env');
  writeFileSync(envPath, 'PORT=not-a-port\nAPI_BASE=https://api.example.com\n');
  process.env.LOGIN_WITH_REZEN_ENV = envPath;

  const warnings = [];
  const realWarn = console.warn;
  console.warn = (message) => warnings.push(String(message));
  try {
    const config = loadConfig();
    assert.equal(config.port, 4500, 'a non-numeric PORT should fall back to the default');
    assert.equal(config.apiBase, 'https://api.example.com', 'API_BASE is read as given, never derived');
    assert.ok(warnings.some((w) => w.includes('not-a-port')), 'the fallback should be announced');
  } finally {
    console.warn = realWarn;
  }
  ok('a non-numeric PORT falls back to the default with a console note');
}

await runFlow('confidential', { clientSecret: 'cs_test_p%ss:w+rd 1' });
await runFlow('public', { clientSecret: '' });
await testSharedVector();
testBadPort();

console.log(`smoke: ${checks} checks passed`);
