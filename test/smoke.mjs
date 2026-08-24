// Offline smoke test — no network beyond 127.0.0.1. Stands up a stub OIDC
// issuer and a stub Real API, boots the sample against them, and drives the
// full sign-in flow (and its failure modes) with fetch.
import assert from 'node:assert';
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import http from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadConfig } from '../src/config.js';
import { createServer } from '../src/server.js';

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
  const kid = 'test-key-1';
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };

  const issuerPort = await getFreePort();
  const issuerUrl = `http://127.0.0.1:${issuerPort}`;
  const apiPort = await getFreePort();
  const apiUrl = `http://127.0.0.1:${apiPort}`;

  const codes = new Map(); // code -> { codeChallenge, redirectUri, nonce, scope }
  const accessTokens = new Set();
  let tokenMode = 'ok';

  function json(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  }

  const issuerServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, issuerUrl);

    if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, {
        issuer: issuerUrl,
        authorization_endpoint: `${issuerUrl}/authorize`,
        token_endpoint: `${issuerUrl}/token`,
        userinfo_endpoint: `${issuerUrl}/userinfo`,
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
        assert.equal(decoded, `${clientId}:${clientSecret}`, 'Basic auth must carry client_id:client_secret');
        assert.equal(form.get('client_id'), null, 'confidential exchange must not also send client_id in the body');
      } else {
        assert.equal(authHeader, undefined, 'public exchange must not send an Authorization header');
        assert.equal(form.get('client_id'), clientId, 'public exchange must send client_id in the body');
      }

      codes.delete(code);
      const accessToken = `real_test_${randomBytes(8).toString('hex')}`;
      accessTokens.add(accessToken);
      const now = Math.floor(Date.now() / 1000);
      const claims = {
        iss: issuerUrl,
        aud: clientId,
        sub: TEST_USER.sub,
        exp: now + 3600,
        iat: now,
        nonce: tokenMode === 'bad-nonce' ? 'not-the-right-nonce' : entry.nonce,
        name: TEST_USER.name,
        email: TEST_USER.email,
        yentaId: TEST_USER.yentaId,
      };
      const idToken = tokenMode === 'bad-alg'
        ? signHS256('not-a-real-secret', { alg: 'HS256', typ: 'JWT' }, claims)
        : signRS256(privateKey, { alg: 'RS256', typ: 'JWT', kid }, claims);

      return json(res, 200, {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 43200,
        scope: entry.scope,
        refresh_token: `rt_test_${randomBytes(8).toString('hex')}`,
        id_token: idToken,
      });
    }

    if (req.method === 'GET' && url.pathname === '/userinfo') {
      const auth = req.headers.authorization;
      const token = auth && auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : undefined;
      if (!token || !accessTokens.has(token)) return json(res, 401, { error: 'invalid_token' });
      return json(res, 200, {
        sub: TEST_USER.sub,
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
    const match = url.pathname.match(/^\/api\/v2\/users\/([^/]+)\/profile$/);
    if (req.method === 'GET' && match) {
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
  assert.ok(homeHtml.includes('Login with reZEN'), `${label}: home page should show the button`);
  ok(`${label}: GET / shows the Login with reZEN button`);

  // Drives one authorize -> callback round trip from a fresh session; returns
  // the cookie the callback should be called with and the callback URL the
  // stub redirected to.
  async function beginFlow() {
    const preRes = await fetch(base + '/');
    let cookie = extractCookie(preRes);
    const loginRes = await fetch(base + '/login', { redirect: 'manual', headers: cookie ? { cookie } : {} });
    assert.equal(loginRes.status, 302, `${label}: /login should redirect`);
    cookie = extractCookie(loginRes) || cookie;
    const authorizeLocation = new URL(loginRes.headers.get('location'));
    assert.equal(authorizeLocation.origin, stub.issuerUrl, `${label}: /login should redirect to the issuer`);
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

  // 2 & 3. /login -> authorize (PKCE S256, state, nonce), follow through to /callback.
  const { cookie, callbackLocation } = await beginFlow();
  ok(`${label}: /login redirects to authorize with PKCE S256, state, and nonce`);

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

  // Negative: a nonce mismatch is rejected.
  stub.setTokenMode('bad-nonce');
  {
    const { cookie: c, callbackLocation: cb } = await beginFlow();
    const res = await fetch(cb.href, { headers: { cookie: c } });
    assert.equal(res.status, 400, `${label}: a nonce mismatch should be rejected`);
  }
  stub.setTokenMode('ok');
  ok(`${label}: callback rejects a nonce mismatch`);

  await new Promise((resolve) => server.close(resolve));
  await stub.close();
}

await runFlow('confidential', { clientSecret: 'cs_test_supersecret123' });
await runFlow('public', { clientSecret: '' });

console.log(`smoke: ${checks} checks passed`);
