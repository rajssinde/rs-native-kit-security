import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { decodeCbor } from '../src/cbor.mts';
import { encodeOid } from '../src/der.mts';
import { AttestationError, createChallenge, InMemoryChallengeStore } from '../src/index.mts';
import { encodeCbor } from './fixtures.mts';

describe('decodeCbor', () => {
  it('round-trips maps, arrays, strings, bytes and integers', () => {
    const value = new Map<string, any>([
      ['n', 1000],
      ['s', 'hello'],
      ['b', Buffer.from([1, 2, 3])],
      ['a', [1, 'x']],
    ]);
    const decoded = decodeCbor(encodeCbor(value)) as Map<string, unknown>;
    assert.equal(decoded.get('n'), 1000);
    assert.equal(decoded.get('s'), 'hello');
    assert.deepEqual(decoded.get('b'), Buffer.from([1, 2, 3]));
    assert.deepEqual(decoded.get('a'), [1, 'x']);
  });

  it('rejects truncated, trailing and unsupported input', () => {
    assert.throws(() => decodeCbor(Buffer.from([0x45, 1, 2])), AttestationError); // 5-byte string, 2 bytes
    assert.throws(() => decodeCbor(Buffer.from([0x01, 0x02])), AttestationError); // trailing byte
    assert.throws(() => decodeCbor(Buffer.from([0x5f])), AttestationError); // indefinite length
    assert.throws(() => decodeCbor(Buffer.from([0xc0, 0x00])), AttestationError); // tag
  });

  it('rejects absurd nesting depth', () => {
    assert.throws(() => decodeCbor(Buffer.alloc(100, 0x81)), AttestationError);
  });
});

describe('encodeOid', () => {
  it('encodes the App Attest nonce OID', () => {
    assert.equal(encodeOid('1.2.840.113635.100.8.2').toString('hex'), '2a864886f763640802');
  });
});

describe('challenges', () => {
  it('createChallenge is long and unique', () => {
    const a = createChallenge();
    assert.equal(Buffer.from(a, 'base64url').length, 32);
    assert.notEqual(a, createChallenge());
  });

  it('InMemoryChallengeStore consumes each challenge exactly once', async () => {
    const store = new InMemoryChallengeStore();
    const challenge = await store.issue();
    assert.equal(await store.consume(challenge), true);
    assert.equal(await store.consume(challenge), false);
    assert.equal(await store.consume('never-issued'), false);
  });

  it('InMemoryChallengeStore rejects expired challenges', async () => {
    let now = 0;
    const store = new InMemoryChallengeStore({ defaultTtlMs: 1000, now: () => now });
    const challenge = await store.issue();
    now = 1001;
    assert.equal(await store.consume(challenge), false);
  });
});
