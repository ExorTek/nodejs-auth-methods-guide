/**
 * JWT Auth — Fastify Test Runner
 *
 * Run:
 *   node --test *.test.js
 */

import { runJwtAuthTests } from '@auth-guide/shared';

runJwtAuthTests({
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3001',
  framework: 'Fastify',
});
