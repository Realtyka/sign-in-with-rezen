import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

// Parses KEY=VALUE lines; comments and blanks are ignored. Values may be
// secrets — they live only in this process and are never logged or rendered.
function parseEnvFile(path) {
  const out = {};
  if (!existsSync(path)) return out;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

// Every environment-specific host is configured, never derived. API_BASE has
// to be set deliberately: an issuer and an API host are a matched pair, and
// guessing one from the other is how a development run ends up calling the
// production API. These are the defaults if .env leaves them out, and both
// are printed at startup so the pair in use is never a guess.
const DEFAULT_ISSUER = 'https://keymaker-oauth.therealbrokerage.com';
const DEFAULT_API_BASE = 'https://yenta.therealbrokerage.com';
const DEFAULT_PORT = 4500;

// A PORT that isn't a number would otherwise fail deep inside listen() with
// an opaque socket error — say so and carry on with the default instead.
function readPort(value) {
  if (value === undefined || value === '') return DEFAULT_PORT;
  const port = Number(value);
  if (Number.isInteger(port) && port >= 0 && port <= 65535) return port;
  console.warn(`PORT is not a valid port number ("${value}") — using ${DEFAULT_PORT} instead.`);
  return DEFAULT_PORT;
}

export function loadConfig() {
  const envPath = process.env.LOGIN_WITH_REZEN_ENV || join(pkgRoot, '.env');
  const env = parseEnvFile(envPath);

  const issuer = (env.ISSUER || DEFAULT_ISSUER).replace(/\/+$/, '');
  const clientId = env.CLIENT_ID || '';
  const clientSecret = env.CLIENT_SECRET || '';
  const redirectUri = env.REDIRECT_URI || 'http://[::1]:4500/callback';
  const scopes = (env.SCOPES || 'openid profile email real.identity ACCOUNT_READ').split(/\s+/).filter(Boolean);
  const port = readPort(env.PORT);
  const apiBase = (env.API_BASE || process.env.API_BASE || DEFAULT_API_BASE).replace(/\/+$/, '');

  return { issuer, clientId, clientSecret, redirectUri, scopes, port, apiBase };
}
