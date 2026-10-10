import assert from 'node:assert/strict';
import { createPublicKey, X509Certificate } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  APPLE_APP_ATTEST_ROOT_CA,
  AttestationError,
  verifyAppAttestAssertion,
  verifyAppAttestAttestation,
} from '../src/index.mts';
import { AAGUID_DEVELOPMENT, makeAssertion, makeAttestation } from './fixtures.mts';

function assertCode(fn: () => unknown, code: string): void {
  assert.throws(fn, (error: unknown) => error instanceof AttestationError && error.code === code);
}

describe('Apple App Attestation Root CA', () => {
  it('is the published Apple root (pinned fingerprint)', () => {
    const root = new X509Certificate(APPLE_APP_ATTEST_ROOT_CA);
    assert.equal(
      root.fingerprint256,
      '1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32'
    );
    assert.match(root.subject, /Apple App Attestation Root CA/);
  });
});

describe('verifyAppAttestAttestation', () => {
  const fixture = makeAttestation();
  const input = {
    attestation: fixture.attestation,
    keyId: fixture.keyId,
    challenge: fixture.challenge,
    appId: fixture.appId,
    rootCertificatePem: fixture.rootPem,
  };

  it('accepts a valid attestation and returns the key to store', () => {
    const key = verifyAppAttestAttestation(input);
    assert.equal(key.keyId, fixture.keyId);
    assert.equal(key.signCount, 0);
    assert.equal(key.environment, 'production');
    assert.equal(Buffer.from(key.receipt, 'base64').toString(), 'receipt-bytes');
    assert.equal(
      createPublicKey(key.publicKeyPem).export({ format: 'jwk' }).x,
      fixture.privateKey.export({ format: 'jwk' }).x // a private JWK carries the public point too
    );
  });

  it('rejects a chain that does not lead to the trusted root (default: Apple)', () => {
    assertCode(
      () => verifyAppAttestAttestation({ ...input, rootCertificatePem: undefined }),
      'UNTRUSTED_CHAIN'
    );
  });

  it('rejects an attestation made for a different challenge', () => {
    assertCode(() => verifyAppAttestAttestation({ ...input, challenge: 'replayed-challenge' }), 'NONCE_MISMATCH');
  });

  it('rejects a certificate bound to a different nonce', () => {
    const forged = makeAttestation({ nonceOverride: Buffer.alloc(32, 7) });
    assertCode(
      () =>
        verifyAppAttestAttestation({
          attestation: forged.attestation,
          keyId: forged.keyId,
          challenge: forged.challenge,
          appId: forged.appId,
          rootCertificatePem: forged.rootPem,
        }),
      'NONCE_MISMATCH'
    );
  });

  it('rejects a keyId that is not the attested key', () => {
    assertCode(
      () => verifyAppAttestAttestation({ ...input, keyId: Buffer.alloc(32, 1).toString('base64') }),
      'KEY_ID_MISMATCH'
    );
  });

  it('rejects an attestation for another app', () => {
    assertCode(() => verifyAppAttestAttestation({ ...input, appId: 'ZZ99YY88XX.com.evil.app' }), 'APP_ID_MISMATCH');
  });

  it('rejects development attestations unless explicitly allowed', () => {
    const dev = makeAttestation({ aaguid: AAGUID_DEVELOPMENT });
    const devInput = {
      attestation: dev.attestation,
      keyId: dev.keyId,
      challenge: dev.challenge,
      appId: dev.appId,
      rootCertificatePem: dev.rootPem,
    };
    assertCode(() => verifyAppAttestAttestation(devInput), 'ENVIRONMENT_MISMATCH');
    assert.equal(
      verifyAppAttestAttestation({ ...devInput, environments: ['development'] }).environment,
      'development'
    );
  });

  it('rejects a non-zero initial counter', () => {
    const used = makeAttestation({ counter: 5 });
    assertCode(
      () =>
        verifyAppAttestAttestation({
          attestation: used.attestation,
          keyId: used.keyId,
          challenge: used.challenge,
          appId: used.appId,
          rootCertificatePem: used.rootPem,
        }),
      'COUNTER_INVALID'
    );
  });

  it('rejects an expired chain', () => {
    assertCode(() => verifyAppAttestAttestation({ ...input, now: new Date('2100-01-01') }), 'CERT_EXPIRED');
  });

  it('rejects garbage input without crashing', () => {
    assert.throws(() => verifyAppAttestAttestation({ ...input, attestation: 'bm90IGNib3I=' }), AttestationError);
  });
});

describe('verifyAppAttestAssertion', () => {
  const fixture = makeAttestation();
  const key = verifyAppAttestAttestation({
    attestation: fixture.attestation,
    keyId: fixture.keyId,
    challenge: fixture.challenge,
    appId: fixture.appId,
    rootCertificatePem: fixture.rootPem,
  });
  const clientData = JSON.stringify({ challenge: 'c-2', body: { amount: 100 } });

  it('accepts a valid assertion and returns the new counter', () => {
    const assertion = makeAssertion({ privateKey: fixture.privateKey, clientData, appId: fixture.appId, counter: 1 });
    const result = verifyAppAttestAssertion({
      assertion,
      clientData,
      publicKeyPem: key.publicKeyPem,
      previousSignCount: 0,
      appId: fixture.appId,
    });
    assert.equal(result.signCount, 1);
  });

  it('rejects an assertion over different client data (tampered request)', () => {
    const assertion = makeAssertion({ privateKey: fixture.privateKey, clientData, appId: fixture.appId, counter: 2 });
    assertCode(
      () =>
        verifyAppAttestAssertion({
          assertion,
          clientData: clientData.replace('100', '100000'),
          publicKeyPem: key.publicKeyPem,
          previousSignCount: 1,
          appId: fixture.appId,
        }),
      'SIGNATURE_INVALID'
    );
  });

  it('rejects a replayed assertion (counter did not increase)', () => {
    const assertion = makeAssertion({ privateKey: fixture.privateKey, clientData, appId: fixture.appId, counter: 3 });
    assertCode(
      () =>
        verifyAppAttestAssertion({
          assertion,
          clientData,
          publicKeyPem: key.publicKeyPem,
          previousSignCount: 3,
          appId: fixture.appId,
        }),
      'COUNTER_REPLAY'
    );
  });

  it('rejects an assertion signed by another key', () => {
    const other = makeAttestation();
    const assertion = makeAssertion({ privateKey: other.privateKey, clientData, appId: fixture.appId, counter: 4 });
    assertCode(
      () =>
        verifyAppAttestAssertion({
          assertion,
          clientData,
          publicKeyPem: key.publicKeyPem,
          previousSignCount: 0,
          appId: fixture.appId,
        }),
      'SIGNATURE_INVALID'
    );
  });
});
