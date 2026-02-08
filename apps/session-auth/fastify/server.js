import 'dotenv/config';
import { createFastifyApp, connectMongoDB } from '@auth-guide/shared';
import fastifyCookie from '@fastify/cookie';
import fastifySession from '@fastify/session';
import fastifyRedis from '@fastify/redis';
import authRoutes from './routes/auth.routes.js';

const PORT = process.env.PORT || 3001;

const app = await createFastifyApp();

await connectMongoDB(process.env.MONGODB_URI);

await app.register(fastifyRedis, {
  url: process.env.REDIS_URL,
});

await app.register(fastifyCookie);

await app.register(fastifySession, {
  secret: process.env.SESSION_SECRET,
  store: {
    get: async (sessionId, callback) => {
      const data = await app.redis.get(`sess:${sessionId}`);
      callback(null, data ? JSON.parse(data) : null);
    },
    set: async (sessionId, session, callback) => {
      await app.redis.set(`sess:${sessionId}`, JSON.stringify(session), 'EX', 86400);
      callback();
    },
    destroy: async (sessionId, callback) => {
      await app.redis.del(`sess:${sessionId}`);
      callback();
    },
  },
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 86400000,
  },
  saveUninitialized: false,
});

await app.register(authRoutes, { prefix: '/api/auth' });

await app.listen({ port: PORT, host: '0.0.0.0' });
