import 'dotenv/config';
import { createFastifyApp, connectMongoDB } from '@auth-guide/shared';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import authRoutes, { ssoRoutes } from './routes/common.routes.js';
import oidcRoutes from './routes/oidc.routes.js';
import samlRoutes from './routes/saml.routes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3005;

const CSP_INLINE =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";

const sendHtml = (reply, filePath) => {
  const html = readFileSync(filePath, 'utf-8');
  return reply
    .header('Content-Type', 'text/html; charset=utf-8')
    .header('Content-Security-Policy', CSP_INLINE)
    .send(html);
};

const app = createFastifyApp();

await connectMongoDB(process.env.MONGODB_URI);

app.get('/', async (request, reply) => {
  return sendHtml(reply, join(__dirname, 'public', 'index.html'));
});

app.get('/validate', async (request, reply) => {
  return sendHtml(reply, join(__dirname, 'public', 'validate.html'));
});

app.register(authRoutes, { prefix: '/api/auth' });
app.register(ssoRoutes, { prefix: '/api/sso' });
app.register(oidcRoutes, { prefix: '/api/sso' });
app.register(samlRoutes, { prefix: '/api/sso' });

await app.listen({ port: PORT, host: '0.0.0.0' });
console.log(`Enterprise SSO (Fastify) running on http://localhost:${PORT}`);
