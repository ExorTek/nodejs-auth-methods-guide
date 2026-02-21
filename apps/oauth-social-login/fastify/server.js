import 'dotenv/config';
import { createFastifyApp, connectMongoDB } from '@auth-guide/shared';
import googleRoutes from './routes/google.routes.js';
import facebookRoutes from './routes/facebook.routes.js';
import providerRoutes from './routes/provider.routes.js';
import commonRoutes from './routes/common.routes.js';

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3003;

const app = await createFastifyApp();

await connectMongoDB(process.env.MONGODB_URI);

/**
 * CSP override helper — relaxes Content-Security-Policy for test dashboard pages.
 * createFastifyApp() registers helmet with strict default CSP that blocks inline scripts.
 * Our HTML test pages use inline <script> tags, so we override CSP per-route.
 */
const CSP_INLINE =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; script-src-attr 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'";

const sendHtml = (reply, filePath) => {
  reply.header('Content-Type', 'text/html').header('Content-Security-Policy', CSP_INLINE).send(readFileSync(filePath));
};

// Static HTML test pages
app.get('/', (request, reply) => sendHtml(reply, join(__dirname, 'public', 'index.html')));
app.get('/validate', (request, reply) => sendHtml(reply, join(__dirname, 'public', 'validate.html')));
app.get('/provider-test', (request, reply) => sendHtml(reply, join(__dirname, 'public', 'provider-test.html')));

// Auth routes — Google, Facebook, common (register/login/exchange/refresh)
await app.register(googleRoutes, { prefix: '/api/auth' });
await app.register(facebookRoutes, { prefix: '/api/auth' });
await app.register(commonRoutes, { prefix: '/api/auth' });

// OAuth Provider routes — when WE are the authorization server
await app.register(providerRoutes, { prefix: '/api/oauth' });

await app.listen({ port: PORT, host: '0.0.0.0' });
