#!/usr/bin/env node
/**
 * Fails if the npm tarball is missing what apps need to build, or contains what
 * it should not. nitrogen/ is git-ignored, so a build that skipped code
 * generation would otherwise publish a package that cannot compile.
 * Run after `yarn prepare`.
 */
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const [{ files }] = JSON.parse(
  execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
);
const paths = files.map((file) => file.path);

const required = [
  'lib/module/index.js',
  'lib/typescript/src/index.d.ts',
  'nitro.json',
  'nitro-compat.json',
  'RsNativeKitSecurity.podspec',
  'android/build.gradle',
  'nitrogen/generated/android/rsnativekit_security+autolinking.cmake',
  'nitrogen/generated/ios/RsNativeKitSecurity+autolinking.rb',
  'nitrogen/generated-legacy/android/rsnativekit_security+autolinking.cmake',
  'nitrogen/generated-legacy/ios/RsNativeKitSecurity+autolinking.rb',
];
const forbidden = [
  /^server\//,
  /^example\//,
  /^scripts\//,
  /^\.claude\//,
  /^\.github\//,
  /__tests__/,
  /\.env/,
];

const missing = required.filter((path) => !paths.includes(path));
const unexpected = paths.filter((path) =>
  forbidden.some((pattern) => pattern.test(path))
);

if (missing.length || unexpected.length) {
  console.error('Package contents check failed.');
  missing.forEach((path) => console.error(`  missing: ${path}`));
  unexpected.forEach((path) => console.error(`  should not ship: ${path}`));
  process.exit(1);
}
console.log(`Package contents OK (${paths.length} files).`);
