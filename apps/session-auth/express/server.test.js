/**
 * Session Auth - Express Test Runner
 *
 * Usage:
 *   node --test *.test.js
 */

import { runSessionAuthTests } from '@auth-guide/shared';

runSessionAuthTests({
  baseUrl: process.env.BASE_URL || 'http://127.0.0.1:3000',
  framework: 'Express',
});
