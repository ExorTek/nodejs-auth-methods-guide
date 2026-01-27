import mongoose from 'mongoose';
import { createClient } from 'redis';
import logger from './logger.js';

const connectMongoDB = async mongoURI => {
  try {
    await mongoose.connect(mongoURI);
    logger.info('Connected to MongoDB');
  } catch (error) {
    logger.error(error);
    throw error;
  }
};

const disconnectMongoDB = async () => {
  try {
    await mongoose.disconnect();
    logger.info('Disconnected from MongoDB');
  } catch (error) {
    logger.error(error);
    throw error;
  }
};

const connectRedis = async redisConfig => {
  const client = createClient(typeof redisConfig === 'string' ? { url: redisConfig } : redisConfig);

  client.on('error', err => {
    logger.error(err);
  });

  client.on('connect', () => {
    logger.info('Connected to Redis');
  });

  await client.connect();
  return client;
};

const disconnectRedis = async client => {
  try {
    await client.quit();
    logger.info('Disconnected from Redis');
  } catch (error) {
    logger.error(error);
    throw error;
  }
};

export { connectMongoDB, disconnectMongoDB, connectRedis, disconnectRedis };
