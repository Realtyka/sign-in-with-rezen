import { loadConfig } from './config.js';
import { createServer } from './server.js';

const config = loadConfig();
const server = createServer(config);

server.listen(config.port, () => {
  console.log(`Login with reZEN sample listening at http://[::1]:${config.port}`);
  console.log(`Issuer:       ${config.issuer}`);
  console.log(`Redirect URI: ${config.redirectUri}`);
  console.log(`Scopes:       ${config.scopes.join(' ')}`);
  console.log(`Client secret: ${config.clientSecret ? 'set' : 'not set (public client)'}`);
});
