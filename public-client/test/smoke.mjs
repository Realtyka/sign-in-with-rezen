// Offline smoke test — no network beyond 127.0.0.1. Part 1 drives the
// protocol module (public/oidc.js) exactly as the browser page would,
// against a stub issuer and a stub Real API that also answer CORS
// preflights, the way a real issuer must for a browser public client.
// Part 2 boots the static server and checks what it serves.
import assert from 'node:assert';
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import http from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  apiCall,
  authorizeUrl,
  discover,
  exchangeCode,
  pkce,
  randomToken,
  userinfo,
  verifyIdToken,
} from '../public/oidc.js';
import { loadConfig } from '../src/config.js';
import { createServer } from '../src/serve.js';

let checks = 0;
function ok(label) {
  checks += 1;
  console.log(`ok - ${label}`);
}

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
const CLIENT_ID = 'app_test_public_client';
const REDIRECT_URI = 'http://127.0.0.1:1/callback';

function withCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, authorization, x-api-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
}

// A stub issuer + a stub resource API, both on 127.0.0.1, both answering
// CORS the way a browser public client requires. tokenMode lets a test
// flip the next id_token's shape (bad alg / nonce / iss / aud / expiry)
// without any extra wiring in the sample itself.
async function startStub() {
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
  let discoveryMode = 'ok';

  function json(res, status, body) {
    withCors(res);
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  }

  const issuerServer = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, issuerUrl);

      if (req.method === 'OPTIONS') {
        withCors(res);
        res.writeHead(204);
        return res.end();
      }

      if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
        return json(res, 200, {
          issuer: discoveryMode === 'bad-issuer' ? `${issuerUrl}/not-the-issuer` : issuerUrl,
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
        assert.equal(q.get('client_id'), CLIENT_ID);
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
        withCors(res);
        res.writeHead(302, { Location: target.href });
        return res.end();
      }

      if (req.method === 'POST' && url.pathname === '/token') {
        let raw = '';
        for await (const chunk of req) raw += chunk;
        const form = new URLSearchParams(raw);
        assert.equal(form.get('grant_type'), 'authorization_code');

        assert.equal(req.headers.authorization, undefined, 'a public exchange must never send Authorization');
        assert.equal(form.get('client_id'), CLIENT_ID, 'a public exchange must send client_id in the body');

        const code = form.get('code');
        const entry = codes.get(code);
        if (!entry) return json(res, 400, { error: 'invalid_grant' });

        const challenge = createHash('sha256').update(form.get('code_verifier') || '').digest('base64url');
        assert.equal(challenge, entry.codeChallenge, 'the code_verifier must hash to the code_challenge sent at /authorize');
        if (form.get('redirect_uri') !== entry.redirectUri) return json(res, 400, { error: 'invalid_grant' });

        codes.delete(code);
        const accessToken = `real_test_${randomBytes(8).toString('hex')}`;
        accessTokens.add(accessToken);
        const now = Math.floor(Date.now() / 1000);
        const multiAud = tokenMode === 'multi-aud-ok' || tokenMode === 'multi-aud-no-azp';
        const claims = {
          iss: tokenMode === 'bad-iss' ? `${issuerUrl}/not-the-issuer` : issuerUrl,
          aud: tokenMode === 'bad-aud' ? 'someone-elses-client' : multiAud ? [CLIENT_ID, 'other-client'] : CLIENT_ID,
          sub: TEST_USER.sub,
          exp: tokenMode === 'expired' ? now - 3600 : tokenMode === 'exp-leeway' ? now - 30 : now + 3600,
          iat: tokenMode === 'future-iat' ? now + 3600 : now,
          nonce: tokenMode === 'bad-nonce' ? 'not-the-right-nonce' : entry.nonce,
          name: TEST_USER.name,
          email: TEST_USER.email,
          yentaId: TEST_USER.yentaId,
        };
        if (tokenMode === 'multi-aud-ok') claims.azp = CLIENT_ID;
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
    } catch (err) {
      json(res, 500, { error: 'test_stub_error', message: err.message });
    }
  });
  await new Promise((resolve) => issuerServer.listen(issuerPort, '127.0.0.1', resolve));

  const apiServer = http.createServer((req, res) => {
    try {
      if (req.method === 'OPTIONS') {
        withCors(res);
        res.writeHead(204);
        return res.end();
      }
      const url = new URL(req.url, apiUrl);
      if (req.method === 'GET' && url.pathname === '/api/v1/users/me') {
        assert.equal(req.headers.authorization, undefined, 'the API call must never send Authorization');
        const key = req.headers['x-api-key'];
        if (!key || !accessTokens.has(key)) return json(res, 401, { error: 'invalid_key' });
        return json(res, 200, TEST_PROFILE);
      }
      return json(res, 404, { error: 'not_found' });
    } catch (err) {
      json(res, 500, { error: 'test_stub_error', message: err.message });
    }
  });
  await new Promise((resolve) => apiServer.listen(apiPort, '127.0.0.1', resolve));

  return {
    issuerUrl,
    apiUrl,
    setTokenMode(mode) { tokenMode = mode; },
    setDiscoveryMode(mode) { discoveryMode = mode; },
    close() {
      return Promise.all([
        new Promise((resolve) => issuerServer.close(resolve)),
        new Promise((resolve) => apiServer.close(resolve)),
      ]);
    },
  };
}

async function runAuthorizeExchange(discovery) {
  const { verifier, challenge } = await pkce();
  const state = randomToken();
  const nonce = randomToken();
  const url = authorizeUrl(discovery, {
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scopes: ['openid', 'profile', 'email', 'real.identity', 'ACCOUNT_READ'],
    state,
    nonce,
    challenge,
  });

  const authorizeRes = await fetch(url, { redirect: 'manual' });
  assert.equal(authorizeRes.status, 302);
  const callbackLocation = new URL(authorizeRes.headers.get('location'));
  assert.equal(callbackLocation.searchParams.get('state'), state);
  assert.equal(callbackLocation.searchParams.get('iss'), discovery.issuer);
  const code = callbackLocation.searchParams.get('code');
  assert.ok(code, 'authorize should hand back a code');

  const tokenRes = await exchangeCode(discovery, { clientId: CLIENT_ID, code, redirectUri: REDIRECT_URI, verifier });
  return { tokenRes, nonce };
}

async function testProtocol() {
  const stub = await startStub();

  const preflight = await fetch(`${stub.issuerUrl}/token`, { method: 'OPTIONS' });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), '*');
  ok('the stub issuer answers a CORS preflight on /token with 204 and Access-Control-Allow-Origin: *');

  const discovery = await discover(stub.issuerUrl);
  assert.equal(discovery.token_endpoint, `${stub.issuerUrl}/token`);
  ok('discover() reads the endpoint list from the discovery document');

  stub.setDiscoveryMode('bad-issuer');
  await assert.rejects(
    () => discover(stub.issuerUrl),
    undefined,
    'discover() should reject a discovery document whose issuer does not match the requested issuer',
  );
  stub.setDiscoveryMode('ok');
  ok('discover() rejects a discovery document whose issuer does not match the requested issuer');

  const { verifier, challenge } = await pkce();
  assert.match(verifier, /^[A-Za-z0-9_-]{40,}$/, 'pkce() verifier should be a URL-safe string of reasonable length');
  const expectedChallenge = createHash('sha256').update(verifier).digest('base64url');
  assert.equal(challenge, expectedChallenge, 'pkce() challenge should be base64url(SHA-256(verifier))');
  ok('pkce() produces an S256 verifier/challenge pair');

  const state = randomToken();
  const nonce = randomToken();
  const url = authorizeUrl(discovery, {
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    scopes: ['openid', 'profile', 'email'],
    state,
    nonce,
    challenge,
  });
  const parsed = new URL(url);
  assert.equal(parsed.origin + parsed.pathname, discovery.authorization_endpoint);
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  assert.equal(parsed.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(parsed.searchParams.get('redirect_uri'), REDIRECT_URI);
  assert.equal(parsed.searchParams.get('scope'), 'openid profile email');
  assert.equal(parsed.searchParams.get('state'), state);
  assert.equal(parsed.searchParams.get('nonce'), nonce);
  assert.equal(parsed.searchParams.get('code_challenge'), challenge);
  assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
  ok('authorizeUrl() builds the /authorize request with PKCE, state, and nonce');

  const { tokenRes, nonce: exchangeNonce } = await runAuthorizeExchange(discovery);
  assert.equal(tokenRes.status, 200, 'the code exchange should succeed');
  assert.ok(tokenRes.body.access_token);
  assert.ok(tokenRes.body.id_token);
  ok('exchangeCode() exchanges the code with no Authorization header and client_id in the body');

  const jwksRes = await fetch(discovery.jwks_uri);
  const jwks = await jwksRes.json();

  const claims = await verifyIdToken(tokenRes.body.id_token, {
    jwks,
    issuer: stub.issuerUrl,
    clientId: CLIENT_ID,
    nonce: exchangeNonce,
  });
  assert.equal(claims.sub, TEST_USER.sub);
  ok('verifyIdToken() accepts a valid RS256 id_token and returns its claims');

  async function expectRejected(mode, label) {
    stub.setTokenMode(mode);
    const { tokenRes: badTokenRes, nonce: badNonce } = await runAuthorizeExchange(discovery);
    assert.equal(badTokenRes.status, 200, `${label}: the exchange itself should still succeed`);
    await assert.rejects(
      () => verifyIdToken(badTokenRes.body.id_token, {
        jwks,
        issuer: stub.issuerUrl,
        clientId: CLIENT_ID,
        nonce: badNonce,
      }),
      undefined,
      label,
    );
    stub.setTokenMode('ok');
    ok(label);
  }

  await expectRejected('bad-alg', 'verifyIdToken rejects an id_token whose alg is not RS256');
  await expectRejected('bad-nonce', 'verifyIdToken rejects a nonce mismatch');
  await expectRejected('bad-iss', 'verifyIdToken rejects an iss mismatch');
  await expectRejected('bad-aud', 'verifyIdToken rejects an aud that does not include this client');
  await expectRejected('expired', 'verifyIdToken rejects an expired id_token');
  await expectRejected('multi-aud-no-azp', 'verifyIdToken rejects a multi-value aud without a matching azp');
  await expectRejected('future-iat', 'verifyIdToken rejects an id_token whose iat is in the future');

  async function expectAccepted(mode, label) {
    stub.setTokenMode(mode);
    const { tokenRes: goodTokenRes, nonce: goodNonce } = await runAuthorizeExchange(discovery);
    assert.equal(goodTokenRes.status, 200, `${label}: the exchange itself should succeed`);
    const acceptedClaims = await verifyIdToken(goodTokenRes.body.id_token, {
      jwks,
      issuer: stub.issuerUrl,
      clientId: CLIENT_ID,
      nonce: goodNonce,
    });
    assert.equal(acceptedClaims.sub, TEST_USER.sub);
    stub.setTokenMode('ok');
    ok(label);
  }

  await expectAccepted('multi-aud-ok', 'verifyIdToken accepts a multi-value aud whose azp names this client');
  await expectAccepted('exp-leeway', 'verifyIdToken accepts an id_token that expired within the clock-skew leeway');

  const accessToken = tokenRes.body.access_token;

  const userinfoRes = await userinfo(discovery, accessToken);
  assert.equal(userinfoRes.status, 200);
  assert.equal(userinfoRes.body.sub, TEST_USER.sub);
  ok('userinfo() sends the access token as Authorization: Bearer');

  const meRes = await apiCall(stub.apiUrl, '/api/v1/users/me', accessToken);
  assert.equal(meRes.status, 200);
  assert.equal(meRes.body.displayName, TEST_PROFILE.displayName);
  ok('apiCall() sends the access token as x-api-key, never Authorization');

  await stub.close();
}

async function testStaticServer() {
  const scratch = mkdtempSync(join(tmpdir(), 'login-with-rezen-public-'));
  const envPath = join(scratch, 'test.env');
  const port = await getFreePort();
  writeFileSync(envPath, [
    'ISSUER=https://keymaker-oauth.therealbrokerage.com',
    `CLIENT_ID=${CLIENT_ID}`,
    'REDIRECT_URI=http://[::1]:4501/callback',
    'SCOPES=openid profile email real.identity ACCOUNT_READ',
    `PORT=${port}`,
    '',
  ].join('\n'));

  process.env.LOGIN_WITH_REZEN_ENV = envPath;
  const config = loadConfig();
  const server = createServer(config);
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${port}`;

  const homeRes = await fetch(base + '/');
  const homeHtml = await homeRes.text();
  assert.equal(homeRes.status, 200);
  assert.ok(homeHtml.includes('Sign in with reZEN'), 'the home page should show the "Sign in with reZEN" heading');
  ok('GET / serves the page with the Sign in with reZEN heading');

  assert.equal(homeRes.headers.get('x-content-type-options'), 'nosniff', 'GET / should send X-Content-Type-Options: nosniff');
  assert.equal(homeRes.headers.get('x-frame-options'), 'DENY', 'GET / should send X-Frame-Options: DENY');
  assert.ok(homeRes.headers.get('content-security-policy'), 'GET / should send a Content-Security-Policy header');
  ok('GET / sends security headers');

  // http.get() sends the path on the wire unmodified — unlike fetch()/URL,
  // which would normalize the '..' segment away before the request is sent.
  function rawGet(path) {
    return new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }).on('error', reject);
    });
  }
  for (const path of ['/../package.json', '/%2e%2e/package.json']) {
    const status = await rawGet(path);
    assert.equal(status, 404, `GET ${path} should not escape the public/ directory`);
  }
  ok('GET /../package.json and /%2e%2e/package.json both 404 — no path traversal out of public/');

  const callbackRes = await fetch(base + '/callback');
  assert.equal(callbackRes.status, 200);
  const callbackHtml = await callbackRes.text();
  assert.ok(callbackHtml.includes('callback.js'));
  ok('GET /callback serves the callback page');

  const configRes = await fetch(base + '/config.js');
  const configBody = await configRes.text();
  assert.equal(configRes.status, 200);
  assert.match(configRes.headers.get('content-type'), /javascript/);
  assert.ok(configBody.includes(config.issuer), 'config.js should carry the issuer');
  assert.ok(configBody.includes(config.clientId), 'config.js should carry the client id');
  assert.ok(configBody.includes(config.redirectUri), 'config.js should carry the redirect URI');
  assert.ok(config.scopes.every((s) => configBody.includes(s)), 'config.js should carry every scope');
  assert.ok(!/secret/i.test(configBody), 'config.js must not contain anything named like a secret — public clients have none');
  ok('GET /config.js exposes issuer, clientId, redirectUri, and scopes, with no secret-like key');

  const appRes = await fetch(base + '/app.js');
  assert.equal(appRes.status, 200);
  assert.match(appRes.headers.get('content-type'), /javascript/);
  ok('GET /app.js is served as JavaScript');

  const oidcRes = await fetch(base + '/oidc.js');
  assert.equal(oidcRes.status, 200);
  assert.match(oidcRes.headers.get('content-type'), /javascript/);
  ok('GET /oidc.js is served as JavaScript');

  const missingRes = await fetch(base + '/nope');
  assert.equal(missingRes.status, 404);
  ok('GET /nope returns 404');

  await new Promise((resolve) => server.close(resolve));
}

async function main() {
  await testProtocol();
  await testStaticServer();
  console.log(`smoke: ${checks} checks passed`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
