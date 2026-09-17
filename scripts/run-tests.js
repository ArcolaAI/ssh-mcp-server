#!/usr/bin/env node

/**
 * 测试运行器
 * 使用 Node.js 内置的测试框架运行所有测试
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'node:url';

// fileURLToPath, not URL.pathname: on Windows pathname yields '/C:/...', which
// is not a directory, so the runner failed before running a test.
const rootDir = fileURLToPath(new URL('..', import.meta.url));

console.log('🧪 运行测试...\n');

try {
  execSync('node scripts/build.js', {
    stdio: 'inherit',
    cwd: rootDir
  });
  execSync('node --test test/*.test.js', {
    stdio: 'inherit',
    cwd: rootDir
  });
} catch (err) {
  process.exit(1);
}
