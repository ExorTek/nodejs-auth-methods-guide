import 'dotenv/config';
import { createFastifyApp, connectMongoDB } from '@auth-guide/shared';
import authRoutes from './routes/auth.routes.js';

const PORT = process.env.PORT || 3001;

const app = await createFastifyApp();

await connectMongoDB(process.env.MONGODB_URI);

await app.register(authRoutes, { prefix: '/api' });

await app.listen({ port: PORT, host: '0.0.0.0' });
