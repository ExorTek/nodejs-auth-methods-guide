import 'dotenv/config';
import { createFastifyApp, connectMongoDB } from '@auth-guide/shared';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import authRoutes from './routes/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3009;

const CSP_INLINE =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";

const sendHtml = (reply, filePath) => {
  const html = readFileSync(filePath, 'utf-8');
  return reply
    .header('Content-Type', 'text/html; charset=utf-8')
    .header('Content-Security-Policy', CSP_INLINE)
    .send(html);
};

const app = await createFastifyApp();
await connectMongoDB(process.env.MONGODB_URI);

app.get('/', async (request, reply) => sendHtml(reply, join(__dirname, 'public', 'index.html')));
app.register(authRoutes, { prefix: '/api/auth' });

try {
  await app.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`Passwordless Auth (Fastify) running on http://localhost:${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
