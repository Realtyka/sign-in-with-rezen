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

// The API host follows the issuer: keymaker-oauth.<domain> -> yenta.<domain>.
// Anything else falls back to the production API host.
function apiBaseFor(issuer) {
  try {
    const host = new URL(issuer).hostname;
    const match = host.match(/^keymaker-oauth\.(.+)$/);
    if (match) return `https://yenta.${match[1]}`;
  } catch {
    // fall through to the default below
  }
  return 'https://yenta.therealbrokerage.com';
}

export function loadConfig() {
  const envPath = process.env.LOGIN_WITH_REZEN_ENV || join(pkgRoot, '.env');
  const env = parseEnvFile(envPath);

  const issuer = (env.ISSUER || 'https://keymaker-oauth.therealbrokerage.com').replace(/\/+$/, '');
  const clientId = env.CLIENT_ID || '';
  const clientSecret = env.CLIENT_SECRET || '';
  const redirectUri = env.REDIRECT_URI || 'http://[::1]:4500/callback';
  const scopes = (env.SCOPES || 'openid profile email real.identity ACCOUNT_READ').split(/\s+/).filter(Boolean);
  const port = Number(env.PORT || 4500);
  const apiBase = (env.API_BASE || process.env.API_BASE || apiBaseFor(issuer)).replace(/\/+$/, '');

  return { issuer, clientId, clientSecret, redirectUri, scopes, port, apiBase };
}
