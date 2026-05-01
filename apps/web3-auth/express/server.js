import 'dotenv/config';
import { createExpressApp, connectMongoDB } from '@auth-guide/shared';
import helmet from 'helmet';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import authRoutes from './routes/index.js';
import { expressErrorHandler } from '@auth-guide/shared';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3001;

const app = createExpressApp();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'script-src': ["'self'", "'unsafe-inline'"],
        'script-src-attr': ["'self'", "'unsafe-inline'"],
      },
    },
  }),
);

await connectMongoDB(process.env.MONGODB_URI);

app.get('/', (req, res) => res.sendFile(join(__dirname, 'public', 'index.html')));

app.use('/api', authRoutes);

app.use(expressErrorHandler);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Web3 Auth (Express) running on http://localhost:${PORT}`);
});
