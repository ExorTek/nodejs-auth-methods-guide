import express from 'express';
import fastify from 'fastify';
import cors from 'cors';
import helmet from 'helmet';
import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import pinoHttp from 'pino-http';
import { expressRequestId, fastifyRequestId } from '../middleware/index.js';
import { fastifyErrorHandler } from './error-handlers.js';
import { logger } from './index.js';

const createExpressApp = () => {
  const app = express();

  app.use(expressRequestId);

  app.use(
    pinoHttp({
      logger: logger,
      autoLogging: {
        ignore: req => req.url === '/health',
      },
      customLogLevel: (req, res, err) => {
        if (res.statusCode >= 500 || err) return 'error';
        if (res.statusCode >= 400) return 'warn';
        return 'info';
      },
      serializers: {
        req: req => ({
          method: req.method,
          url: req.url,
          host: req.headers?.host,
          remoteAddress: req.socket?.remoteAddress,
          remotePort: req.socket?.remotePort,
        }),
        res: res => ({
          statusCode: res.statusCode,
        }),
      },
    }),
  );

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: false }));

  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || '*',
      credentials: true,
    }),
  );
  app.use(helmet({}));

  app.get('/health', (req, res) => {
    res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
    });
  });

  return app;
};

const createFastifyApp = async () => {
  const app = fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:yyyy-mm-dd HH:MM:ss',
          ignore: 'pid,hostname',
          singleLine: true,
        },
      },
    },
  });

  await app.register(fastifyCors, {
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  });

  await app.register(fastifyHelmet, {});

  app.get('/health', {
    logLevel: 'silent',
    handler: async (request, reply) => {
      return {
        success: true,
        timestamp: new Date().toISOString(),
      };
    },
  });

  app.setErrorHandler(fastifyErrorHandler);
  app.setGenReqId(fastifyRequestId);

  return app;
};

export { createExpressApp, createFastifyApp };
