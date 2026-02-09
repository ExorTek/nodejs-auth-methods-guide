import 'dotenv/config';
import { createExpressApp, connectMongoDB, expressErrorHandler, logger } from '@auth-guide/shared';
import authRoutes from './routes/auth.routes.js';

const PORT = process.env.PORT || 3000;

const app = createExpressApp();

await connectMongoDB(process.env.MONGODB_URI);

app.use('/api/auth', authRoutes);

app.use(expressErrorHandler);

app.listen(PORT, () => {
  logger.info(`JWT Auth Server running on http://localhost:${PORT}`);
});
