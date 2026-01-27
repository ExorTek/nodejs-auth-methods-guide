import 'dotenv/config';
import { createExpressApp, connectMongoDB, connectRedis, expressErrorHandler } from '@auth-guide/shared';
import session from 'express-session';
import { RedisStore } from 'connect-redis';
import authRoutes from './routes/auth.routes.js';

const PORT = process.env.PORT || 3000;

const app = createExpressApp();

await connectMongoDB(process.env.MONGODB_URI);

const redisClient = await connectRedis(process.env.REDIS_URL);

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  }),
);

app.use('/api/auth', authRoutes);

app.use(expressErrorHandler);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
