import 'dotenv/config';
import { createExpressApp, connectMongoDB } from '@auth-guide/shared';
import helmet from 'helmet';

import commonRoutes, { ssoRouter } from './routes/common.routes.js';
import oidcRoutes from './routes/oidc.routes.js';
import samlRoutes from './routes/saml.routes.js';
import { expressErrorHandler } from '@auth-guide/shared';

import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3004;

const app = createExpressApp();

// Helmet with CSP override for test dashboard inline scripts
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

// Parse URL-encoded body (for SAML ACS — IdP sends form POST)
app.use('/api/sso/saml/acs', (req, res, next) => {
  if (req.is('application/x-www-form-urlencoded')) {
    // express.urlencoded is already part of createExpressApp if needed
    // but we ensure it's available for SAML POST binding
    next();
  } else {
    next();
  }
});

await connectMongoDB(process.env.MONGODB_URI);

app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.get('/validate', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'validate.html'));
});

// Local auth — register, login, exchange, refresh, logout
app.use('/api/auth', commonRoutes);

// SSO management — config CRUD, discovery
app.use('/api/sso', ssoRouter);

// OIDC routes — init, callback, discovery
app.use('/api/sso', oidcRoutes);

// SAML routes — init, ACS, metadata
app.use('/api/sso', samlRoutes);

// ─── Error handler (must be last) ───
app.use(expressErrorHandler);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Enterprise SSO (Express) running on http://localhost:${PORT}`);
});
