#!/usr/bin/env node
/**
 * Prints the version increment the commits since the last release call for:
 * none, patch, minor or major. The release workflow publishes only when this
 * is not "none", so docs, chore and CI changes never produce a release.
 *
 * Breaking changes bump minor while the package is on 0.x, so going to 1.0.0
 * is a deliberate choice (run the Release workflow by hand with "major").
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HEADER = /^(\w+)(?:\([^)]*\))?(!)?: /;
const BREAKING_FOOTER = /^BREAKING[ -]CHANGE: /m;
const RANK = { none: 0, patch: 1, minor: 2, major: 3 };

export function bumpForCommit(message) {
  const match = HEADER.exec(message);
  if (!match) return 'none';
  if (match[2] || BREAKING_FOOTER.test(message)) return 'major';
  if (match[1] === 'feat') return 'minor';
  if (['fix', 'perf', 'revert'].includes(match[1])) return 'patch';
  return 'none';
}

export function decideBump(messages, currentVersion) {
  const bump = messages
    .map(bumpForCommit)
    .reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'none');
  return bump === 'major' && currentVersion.startsWith('0.') ? 'minor' : bump;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const git = (...args) =>
    execFileSync('git', args, { cwd: root, encoding: 'utf8' });
  const tag = git(
    'describe',
    '--tags',
    '--abbrev=0',
    '--match',
    'v[0-9]*'
  ).trim();
  const messages = git('log', `${tag}..HEAD`, '--format=%B%x00')
    .split('\0')
    .map((m) => m.trim())
    .filter(Boolean);
  const { version } = JSON.parse(
    readFileSync(join(root, 'package.json'), 'utf8')
  );
  console.log(decideBump(messages, version));
}
