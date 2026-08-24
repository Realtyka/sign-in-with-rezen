import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { apiCall, authorizeUrl, discover, exchangeCode, pkce, userinfo, verifyIdToken } from './oidc.js';

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function requestUrl(req) {
  return new URL(req.url, `http://${req.headers.host || 'localhost'}`);
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
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f7; color: #1d1d1f; }
  .wrap { max-width: 640px; margin: 0 auto; padding: 3rem 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .75rem; }
  h2 { font-size: 1rem; margin: 1.5rem 0 .5rem; color: #444; }
  p { line-height: 1.5; }
  table.kv { border-collapse: collapse; width: 100%; }
  table.kv td { padding: .35rem .6rem; border-bottom: 1px solid #ddd; font-size: .9rem; }
  table.kv td:first-child { color: #666; font-family: ui-monospace, monospace; width: 30%; }
  ol.steps { padding-left: 1.2rem; font-size: .9rem; color: #333; }
  .button { display: inline-block; background: #0b5fff; color: #fff; text-decoration: none; padding: .65rem 1.3rem; border-radius: 6px; font-weight: 600; }
  .muted { color: #777; }
  code { background: #eee; padding: .1rem .35rem; border-radius: 4px; }
`;

function layout(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="wrap">${body}</div>
</body>
</html>`;
}

function errorPage(message) {
  return layout('Sign-in failed', `
    <h1>Sign-in failed</h1>
    <p>${escapeHtml(message)}</p>
    <p><a href="/">Start again</a></p>
  `);
}

function homePage(sessionData) {
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
      ? `<h2>Profile</h2><table class="kv">`
        + `<tr><td>displayName</td><td>${escapeHtml(String(sessionData.profile.displayName))}</td></tr>`
        + `<tr><td>type</td><td>${escapeHtml(String(sessionData.profile.type))}</td></tr>`
        + `</table>`
      : `<h2>Profile</h2><p class="muted">Skipped — no yentaId claim was released for the granted scopes.</p>`;
    const steps = (sessionData.steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join('');
    return layout('Signed in with reZEN', `
      <h1>Signed in with reZEN</h1>
      <h2>Identity</h2>
      ${identityTable}
      <h2>Granted scope</h2>
      <p><code>${escapeHtml(sessionData.scope || '')}</code></p>
      ${profileBlock}
      <h2>What happened</h2>
      <ol class="steps">${steps}</ol>
      <p><a href="/logout">Log out</a></p>
    `);
  }
  return layout('Login with reZEN', `
    <h1>Login with reZEN</h1>
    <p>This sample runs the authorization code flow with PKCE against a reZEN OIDC
    issuer, verifies your identity, and calls one Real API on your behalf.</p>
    <p><a class="button" href="/login">Login with reZEN</a></p>
  `);
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

  function ensureSession(req, res) {
    const existing = getSession(req);
    if (existing) return existing;
    const id = randomBytes(24).toString('base64url');
    const data = {};
    sessions.set(id, data);
    res.setHeader('Set-Cookie', `sid=${id}; HttpOnly; Path=/; SameSite=Lax`);
    return { id, data };
  }

  const handler = async (req, res) => {
    const url = requestUrl(req);
    try {
      if (req.method === 'GET' && url.pathname === '/') {
        const session = getSession(req);
        return sendHtml(res, homePage(session?.data));
      }

      if (req.method === 'GET' && url.pathname === '/login') {
        const session = ensureSession(req, res);
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

        const errParam = url.searchParams.get('error');
        if (errParam) {
          return sendHtml(
            res,
            errorPage(mapAuthorizeError(errParam, url.searchParams.get('error_description'))),
            400,
          );
        }

        const flow = session.data.flow;
        if (!flow || url.searchParams.get('state') !== flow.state) {
          return sendHtml(res, errorPage('The state parameter did not match — start again.'), 400);
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

        const userinfoRes = await userinfo(discovery, accessToken);
        steps.push(userinfoRes.status === 200 ? 'Userinfo fetched' : `Userinfo call failed (HTTP ${userinfoRes.status})`);

        let profile;
        const yentaId = claims.yentaId;
        if (yentaId) {
          const profileRes = await apiCall(config.apiBase, `/api/v2/users/${yentaId}/profile`, accessToken);
          if (profileRes.status === 200) {
            profile = {
              displayName: profileRes.body.displayName ?? '(not present)',
              type: profileRes.body.type ?? '(not present)',
            };
            steps.push('Profile fetched with x-api-key (200)');
          } else {
            steps.push(`Profile call failed (HTTP ${profileRes.status})`);
          }
        } else {
          steps.push('Profile call skipped — no yentaId claim was released');
        }

        session.data.identity = { sub: claims.sub, name: claims.name, email: claims.email, yentaId };
        session.data.scope = tokenRes.body.scope || '';
        session.data.profile = profile;
        session.data.steps = steps;
        session.data.flow = undefined;

        return redirect(res, '/');
      }

      if (req.method === 'GET' && url.pathname === '/logout') {
        const session = getSession(req);
        if (session) sessions.delete(session.id);
        res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
        return redirect(res, '/');
      }

      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not found');
    } catch (err) {
      console.error('unexpected error:', err?.message || err);
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('unexpected error');
    }
  };

  return http.createServer(handler);
}
