import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from './config.js';

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = resolve(pkgRoot, 'public');

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

// Extensionless routes the page navigates to directly.
const ROUTES = {
  '/': 'index.html',
  '/callback': 'callback.html',
};

function configScript(config) {
  const payload = {
    issuer: config.issuer,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scopes: config.scopes,
    apiBase: config.apiBase,
  };
  return `export default ${JSON.stringify(payload, null, 2)};\n`;
}

function notFound(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
}

// A zero-dependency static file server for public/, plus one generated
// route (/config.js) built from the loaded .env — the browser never reads
// .env directly, and nothing secret ever passes through here (there is no
// client secret for a public client to leak).
export function createServer(config) {
  const handler = async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('method not allowed');
    }

    const pathname = new URL(req.url, 'http://placeholder').pathname;

    if (pathname === '/config.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' });
      return res.end(configScript(config));
    }

    const relative = ROUTES[pathname] || pathname.replace(/^\/+/, '');
    if (!relative) return notFound(res);

    const filePath = resolve(publicDir, relative);
    if (filePath !== publicDir && !filePath.startsWith(publicDir + sep)) return notFound(res);
    if (!existsSync(filePath)) return notFound(res);

    try {
      const body = await readFile(filePath);
      const type = CONTENT_TYPES[extname(filePath)] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type });
      res.end(body);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`unexpected error: ${err.message}`);
    }
  };

  return http.createServer(handler);
}

// Boot only when this file is run directly (`npm start`) — not when the
// test suite imports createServer to boot its own instance on a free port.
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.port, () => {
    console.log(`Login with reZEN (public client) listening at http://[::1]:${config.port}`);
    console.log(`Issuer:       ${config.issuer}`);
    console.log(`Redirect URI: ${config.redirectUri}`);
    console.log(`Scopes:       ${config.scopes.join(' ')}`);
  });
}
