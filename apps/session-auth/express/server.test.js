/**
 * Session Auth - Express Test Runner
 *
 * Prerequisites:
 *   1. MongoDB and Redis running (docker compose up -d)
 *   2. Express server running (yarn dev)
 *
 * Usage:
 *   node --test test.js
 */

import { runAuthTests } from '@auth-guide/shared';

runAuthTests({
  baseUrl: process.env.BASE_URL || 'http://127.0.0.1:3000',
  framework: 'Express',
});
