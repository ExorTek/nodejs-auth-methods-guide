/**
 * OAuth Social Login — Express Test Runner
 *
 * Run:
 *   node --test *.test.js
 */

import { runOAuthTests } from '@auth-guide/shared';

runOAuthTests({
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
  framework: 'Express',
});
