import 'dotenv/config';
import passport from 'passport';
import { createExpressApp, connectMongoDB, expressErrorHandler } from '@auth-guide/shared';
import googleRoutes from './routes/google.routes.js';
import facebookRoutes from './routes/facebook.routes.js';
import providerRoutes from './routes/provider.routes.js';
import commonRoutes from './routes/common.routes.js';
import passportRoutes from './routes/passport.routes.js';
import googleStrategy from './strategies/google.strategy.js';
import facebookStrategy from './strategies/facebook.strategy.js';
import helmet from 'helmet';

import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3002;

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

passport.use(googleStrategy);
passport.use(facebookStrategy);
app.use(passport.initialize());

app.use('/api/auth', googleRoutes);
app.use('/api/auth', facebookRoutes);
app.use('/api/auth', commonRoutes);
app.use('/api/auth/passport', passportRoutes);
app.use('/api/oauth', providerRoutes);

app.get('/validate/auth/error', (req, res) => {
  return res.status(400).json({ error: 'Authentication failed' });
});

app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.get('/validate', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'validate.html'));
});

app.get('/provider-test', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'provider-test.html'));
});

app.use(expressErrorHandler);

app.listen(PORT, () => {
  console.log(`OAuth Social Login server: http://localhost:${PORT}`);
});
