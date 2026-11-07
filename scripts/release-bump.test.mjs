import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bumpForCommit, decideBump } from './release-bump.mjs';

test('commit types map to the expected increment', () => {
  assert.equal(bumpForCommit('feat: add check'), 'minor');
  assert.equal(bumpForCommit('feat(android): add check'), 'minor');
  assert.equal(bumpForCommit('fix: false positive'), 'patch');
  assert.equal(bumpForCommit('perf: faster scan'), 'patch');
  assert.equal(bumpForCommit('revert: undo check'), 'patch');
});

test('commits that do not change the package never release', () => {
  for (const message of [
    'docs: update readme',
    'chore: release 1.2.3 [skip ci]',
    'chore(deps): bump jest',
    'ci: add job',
    'Merge pull request #1 from x/feat: y',
    'feature: not a conventional type',
  ]) {
    assert.equal(bumpForCommit(message), 'none', message);
  }
});

test('breaking markers are detected in the header and in the footer', () => {
  assert.equal(bumpForCommit('feat!: new result type'), 'major');
  assert.equal(bumpForCommit('fix(ios)!: rename'), 'major');
  assert.equal(bumpForCommit('refactor: x\n\nBREAKING CHANGE: y'), 'major');
  assert.equal(bumpForCommit('refactor: x\n\nBREAKING-CHANGE: y'), 'major');
  assert.equal(
    bumpForCommit('fix: x\n\nnot a BREAKING CHANGE: mid-line'),
    'patch'
  );
});

test('the largest increment wins', () => {
  assert.equal(decideBump(['fix: a', 'feat: b', 'docs: c'], '1.0.0'), 'minor');
  assert.equal(decideBump(['fix: a', 'feat!: b'], '1.0.0'), 'major');
  assert.equal(decideBump(['docs: a', 'chore: b'], '1.0.0'), 'none');
  assert.equal(decideBump([], '1.0.0'), 'none');
});

test('breaking changes stay on minor while the package is on 0.x', () => {
  assert.equal(decideBump(['feat!: b'], '0.1.0'), 'minor');
  assert.equal(decideBump(['fix: a'], '0.1.0'), 'patch');
});
