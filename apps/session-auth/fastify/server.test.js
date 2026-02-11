/**
 * Session Auth - Fastify Test Runner
 * Usage:
 *   node --test *.test.js
 */

import { runSessionAuthTests } from '@auth-guide/shared';

runSessionAuthTests({
  baseUrl: process.env.BASE_URL || 'http://127.0.0.1:3001',
  framework: 'Fastify',
});
