import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  AttestationError,
  fetchKeyAttestationRevocations,
  GOOGLE_KEY_ATTESTATION_ROOTS,
  KEY_ATTESTATION_STATUS_URL,
  verifyKeyAttestation,
  type KeyAttestationInput,
} from '../src/index.mts';
import { KEY_ATTESTATION_SIGNING_DIGEST, makeKeyAttestation, type KeyDescriptionOptions } from './fixtures.mts';

function assertCode(fn: () => unknown, code: string): void {
  assert.throws(fn, (error: unknown) => error instanceof AttestationError && error.code === code);
}

function inputFor(options: KeyDescriptionOptions = {}, overrides: Partial<KeyAttestationInput> = {}): KeyAttestationInput {
  const fixture = makeKeyAttestation(options);
  return {
    certificateChain: fixture.certificateChain,
    challenge: 'key-attestation-challenge',
    packageName: 'com.example.app',
    certificateSha256Digests: [KEY_ATTESTATION_SIGNING_DIGEST.toString('hex')],
    revokedSerials: new Set(),
    rootCertificatesPem: [fixture.rootPem],
    ...overrides,
  };
}

describe('Google hardware attestation roots', () => {
  it('are the published roots (pinned fingerprints)', () => {
    const fingerprints = GOOGLE_KEY_ATTESTATION_ROOTS.map((pem) => new X509Certificate(pem).fingerprint256);
    assert.deepEqual(fingerprints, [
      'CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC',
      '6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0',
    ]);
  });
});

describe('verifyKeyAttestation', () => {
  const valid = inputFor();

  it('accepts a locked, verified, hardware-backed attestation for this app', () => {
    const verdict = verifyKeyAttestation(valid);
    assert.equal(verdict.ok, true, verdict.failures.join());
    assert.deepEqual(verdict.failures, []);
    assert.equal(verdict.attestationSecurityLevel, 'TrustedEnvironment');
    assert.equal(verdict.deviceLocked, true);
    assert.equal(verdict.verifiedBootState, 'Verified');
    assert.equal(verdict.verifiedBootKey, 'ab'.repeat(32));
    assert.equal(verdict.osVersion, 150000);
    assert.equal(verdict.osPatchLevel, 202609);
    assert.equal(verdict.vendorPatchLevel, 20260905);
    assert.deepEqual(verdict.packageNames, ['com.example.app']);
  });

  it('reports StrongBox', () => {
    assert.equal(verifyKeyAttestation(inputFor({ securityLevel: 2 })).keyMintSecurityLevel, 'StrongBox');
  });

  it('reports an unlocked bootloader (what root needs, and what hiding tools cannot change)', () => {
    const verdict = verifyKeyAttestation(inputFor({ deviceLocked: false, verifiedBootState: 2 }));
    assert.equal(verdict.ok, false);
    assert.deepEqual(verdict.failures, ['BOOTLOADER_UNLOCKED', 'BOOT_STATE_NOT_VERIFIED']);
    assert.equal(verdict.verifiedBootState, 'Unverified');
  });

  it('reports a relocked custom OS (self-signed boot) without calling it unlocked', () => {
    const verdict = verifyKeyAttestation(inputFor({ verifiedBootState: 1 }));
    assert.deepEqual(verdict.failures, ['BOOT_STATE_NOT_VERIFIED']);
  });

  it('fails closed when the root of trust is missing', () => {
    const verdict = verifyKeyAttestation(inputFor({ omitRootOfTrust: true }));
    assert.deepEqual(verdict.failures, ['BOOTLOADER_UNLOCKED', 'BOOT_STATE_NOT_VERIFIED']);
    assert.equal(verdict.deviceLocked, undefined);
  });

  it('reports software-only attestation', () => {
    assert.ok(verifyKeyAttestation(inputFor({ securityLevel: 0 })).failures.includes('NOT_HARDWARE_BACKED'));
  });

  it('reports another app or signing key', () => {
    assert.deepEqual(verifyKeyAttestation(inputFor({ packageName: 'com.attacker.app' })).failures, ['PACKAGE_MISMATCH']);
    assert.deepEqual(verifyKeyAttestation(inputFor({ signatureDigest: Buffer.alloc(32, 1) })).failures, [
      'CERTIFICATE_MISMATCH',
    ]);
  });

  it('rejects a different challenge (replay)', () => {
    assertCode(() => verifyKeyAttestation({ ...valid, challenge: 'another-challenge' }), 'CHALLENGE_MISMATCH');
  });

  it('rejects a chain that does not end at a trusted root', () => {
    assertCode(() => verifyKeyAttestation({ ...valid, rootCertificatesPem: undefined }), 'UNTRUSTED_CHAIN');
  });

  it('accepts a chain that omits the root but is signed by it', () => {
    assert.equal(verifyKeyAttestation({ ...valid, certificateChain: valid.certificateChain.slice(0, 2) }).ok, true);
  });

  it('rejects a broken chain', () => {
    const [leaf, intermediate, root] = valid.certificateChain;
    assertCode(() => verifyKeyAttestation({ ...valid, certificateChain: [intermediate!, leaf!, root!] }), 'UNTRUSTED_CHAIN');
  });

  it('rejects a leaf forged with a genuine device key', () => {
    const fixture = makeKeyAttestation({ forgedLeaf: {} });
    assertCode(
      () =>
        verifyKeyAttestation({
          ...valid,
          certificateChain: fixture.certificateChain,
          rootCertificatesPem: [fixture.rootPem],
        }),
      'UNTRUSTED_CHAIN'
    );
  });

  it('rejects revoked device keys, whatever the serial formatting', () => {
    const fixture = makeKeyAttestation();
    const base = { ...valid, certificateChain: fixture.certificateChain, rootCertificatesPem: [fixture.rootPem] };
    assert.equal(verifyKeyAttestation(base).ok, true);
    for (const serial of fixture.serials.slice(0, 2)) {
      const googleFormat = serial.toLowerCase().replace(/^0+/, '');
      assertCode(() => verifyKeyAttestation({ ...base, revokedSerials: new Set([googleFormat]) }), 'CERT_REVOKED');
      assertCode(() => verifyKeyAttestation({ ...base, revokedSerials: new Set([`00${serial}`]) }), 'CERT_REVOKED');
    }
  });

  it('rejects an expired intermediate', () => {
    assertCode(() => verifyKeyAttestation({ ...valid, now: new Date(Date.now() + 2 * 365 * 86_400_000) }), 'CERT_EXPIRED');
  });

  it('rejects malformed input', () => {
    assertCode(() => verifyKeyAttestation({ ...valid, certificateChain: [] }), 'MALFORMED');
    assertCode(() => verifyKeyAttestation({ ...valid, certificateChain: ['bm90IGEgY2VydA==', 'eA=='] }), 'MALFORMED');
  });
});

describe('fetchKeyAttestationRevocations', () => {
  it('returns every listed serial from Google\'s status list format', async () => {
    let requested = '';
    const fakeFetch = (async (url: string) => {
      requested = url;
      return new Response(
        JSON.stringify({
          entries: {
            '6681152659205225093': { status: 'REVOKED', reason: 'KEY_COMPROMISE' },
            C35747A084470C3135AEEFE2B8D40CD6: { status: 'SUSPENDED', reason: 'SOFTWARE_FLAW' },
          },
        })
      );
    }) as unknown as typeof fetch;
    const serials = await fetchKeyAttestationRevocations(fakeFetch);
    assert.equal(requested, KEY_ATTESTATION_STATUS_URL);
    assert.deepEqual([...serials], ['6681152659205225093', 'c35747a084470c3135aeefe2b8d40cd6']);
  });

  it('fails instead of returning an empty list', async () => {
    const down = (async () => new Response('', { status: 503 })) as unknown as typeof fetch;
    await assert.rejects(fetchKeyAttestationRevocations(down), (e: unknown) => e instanceof AttestationError && e.code === 'REVOCATION_LIST_UNAVAILABLE');
    const empty = (async () => new Response('{}')) as unknown as typeof fetch;
    await assert.rejects(fetchKeyAttestationRevocations(empty), AttestationError);
  });
});
