import { createHash, createPublicKey, verify as verifySignature, X509Certificate, type KeyObject } from 'node:crypto';
import { decodeCbor, type CborValue } from './cbor.mts';
import { findExtension, readAppAttestNonce } from './der.mts';
import { AttestationError } from './errors.mts';

/**
 * Apple App Attestation Root CA, from
 * https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
 * SHA-256 fingerprint 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32
 * (valid until 2045-03-15; checked by test).
 */
export const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
`;

const NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';
const AAGUID_PRODUCTION = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);
const AAGUID_DEVELOPMENT = Buffer.from('appattestdevelop');

export type AppAttestEnvironment = 'production' | 'development';

export interface AppAttestAttestationInput {
  /** Base64 attestation object from `attestAppAttestKey()`. */
  attestation: string;
  /** The `keyId` the app attested (base64). */
  keyId: string;
  /** The exact challenge string the app passed to `attestAppAttestKey()`. */
  challenge: string;
  /** `TEAMID.bundle.identifier` of your app. */
  appId: string;
  /** Accepted environments. Default: production only. */
  environments?: AppAttestEnvironment[];
  /** Override the trust anchor (tests only). Default: Apple App Attestation Root CA. */
  rootCertificatePem?: string;
  /** Verification time. Default: now. */
  now?: Date;
}

export interface VerifiedAppAttestKey {
  keyId: string;
  /** Store this, keyed by `keyId`; assertions are verified against it. */
  publicKeyPem: string;
  /** Starts at 0; store it and pass it to `verifyAppAttestAssertion()`. */
  signCount: number;
  environment: AppAttestEnvironment;
  /** Base64 receipt for Apple's fraud-metric API (optional use). */
  receipt: string;
}

export interface AppAttestAssertionInput {
  /** Base64 assertion from `generateAppAttestAssertion()`. */
  assertion: string;
  /** The exact `clientData` string the app signed. */
  clientData: string;
  /** Stored from attestation. */
  publicKeyPem: string;
  /** Last stored `signCount` for this key. */
  previousSignCount: number;
  appId: string;
}

export interface VerifiedAppAttestAssertion {
  /** Store this as the key's new `signCount`. */
  signCount: number;
}

const sha256 = (...parts: Buffer[]): Buffer => {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
};

function fail(code: string, message: string): never {
  throw new AttestationError(code, message);
}

function mapGet(value: CborValue, key: string): CborValue | undefined {
  return value instanceof Map ? value.get(key) : undefined;
}

function asBuffer(value: CborValue | undefined, what: string): Buffer {
  return Buffer.isBuffer(value) ? value : fail('MALFORMED', `${what} is missing or not bytes`);
}

/** authenticatorData layout: rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | credIdLen(2) | credId | ...] */
function parseAuthenticatorData(authData: Buffer, withCredential: boolean) {
  if (authData.length < 37) fail('MALFORMED', 'authenticator data is too short');
  const rpIdHash = authData.subarray(0, 32);
  const signCount = authData.readUInt32BE(33);
  if (!withCredential) return { rpIdHash, signCount };

  if (authData.length < 55) fail('MALFORMED', 'authenticator data has no attested credential');
  const aaguid = authData.subarray(37, 53);
  const credentialIdLength = authData.readUInt16BE(53);
  if (authData.length < 55 + credentialIdLength) fail('MALFORMED', 'credential ID runs past the data');
  const credentialId = authData.subarray(55, 55 + credentialIdLength);
  return { rpIdHash, signCount, aaguid, credentialId };
}

function checkValidity(certificate: X509Certificate, now: Date, name: string): void {
  if (now < new Date(certificate.validFrom) || now > new Date(certificate.validTo)) {
    fail('CERT_EXPIRED', `${name} certificate is not valid at ${now.toISOString()}`);
  }
}

/** Uncompressed EC point (0x04 | X | Y) of a P-256 public key. */
function rawPublicKey(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    fail('MALFORMED', 'credential certificate key is not P-256');
  }
  return Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

/**
 * Verifies a one-time App Attest key attestation (Apple, "Validating apps
 * that connect to your server", steps 1–9). On success, store
 * `publicKeyPem` and `signCount` against `keyId`; on failure an
 * `AttestationError` explains which step failed.
 */
export function verifyAppAttestAttestation(input: AppAttestAttestationInput): VerifiedAppAttestKey {
  const now = input.now ?? new Date();
  const environments = input.environments ?? ['production'];
  const object = decodeCbor(Buffer.from(input.attestation, 'base64'));

  if (mapGet(object, 'fmt') !== 'apple-appattest') fail('MALFORMED', 'attestation format is not apple-appattest');
  const attStmt = mapGet(object, 'attStmt');
  const x5c = mapGet(attStmt ?? null, 'x5c');
  if (!Array.isArray(x5c) || x5c.length < 2) fail('MALFORMED', 'attestation has no certificate chain');
  const authData = asBuffer(mapGet(object, 'authData'), 'authData');
  const receipt = asBuffer(mapGet(attStmt ?? null, 'receipt'), 'receipt');

  // 1. Certificate chain: credCert ← intermediate ← Apple App Attestation Root CA.
  const credCert = new X509Certificate(asBuffer(x5c[0], 'credential certificate'));
  const intermediate = new X509Certificate(asBuffer(x5c[1], 'intermediate certificate'));
  const root = new X509Certificate(input.rootCertificatePem ?? APPLE_APP_ATTEST_ROOT_CA);
  if (!intermediate.checkIssued(root) || !intermediate.verify(root.publicKey)) {
    fail('UNTRUSTED_CHAIN', 'intermediate certificate is not signed by the App Attest root');
  }
  if (!credCert.checkIssued(intermediate) || !credCert.verify(intermediate.publicKey)) {
    fail('UNTRUSTED_CHAIN', 'credential certificate is not signed by the intermediate');
  }
  checkValidity(root, now, 'root');
  checkValidity(intermediate, now, 'intermediate');
  checkValidity(credCert, now, 'credential');

  // 2–4. nonce = SHA256(authData | SHA256(challenge)) must equal the credCert extension.
  const nonce = sha256(authData, sha256(Buffer.from(input.challenge, 'utf8')));
  const extension = findExtension(credCert.raw, NONCE_EXTENSION_OID) ?? fail('NONCE_MISMATCH', 'credential certificate has no nonce extension');
  if (!readAppAttestNonce(extension).equals(nonce)) {
    fail('NONCE_MISMATCH', 'attestation is not bound to this challenge');
  }

  // 5. keyId = SHA256(public key).
  const publicKey = credCert.publicKey;
  const keyId = Buffer.from(input.keyId, 'base64');
  if (!sha256(rawPublicKey(publicKey)).equals(keyId)) {
    fail('KEY_ID_MISMATCH', "keyId doesn't match the attested public key");
  }

  const parsed = parseAuthenticatorData(authData, true);
  // 6. rpIdHash = SHA256(appId).
  if (!parsed.rpIdHash.equals(sha256(Buffer.from(input.appId, 'utf8')))) {
    fail('APP_ID_MISMATCH', `attestation is not for app ${input.appId}`);
  }
  // 7. A fresh key has never signed anything.
  if (parsed.signCount !== 0) fail('COUNTER_INVALID', 'attestation counter is not 0');
  // 8. Environment.
  const environment: AppAttestEnvironment | undefined = parsed.aaguid!.equals(AAGUID_PRODUCTION)
    ? 'production'
    : parsed.aaguid!.equals(AAGUID_DEVELOPMENT)
      ? 'development'
      : undefined;
  if (!environment || !environments.includes(environment)) {
    fail('ENVIRONMENT_MISMATCH', `attestation environment ${environment ?? 'unknown'} is not accepted`);
  }
  // 9. credentialId = keyId.
  if (!parsed.credentialId!.equals(keyId)) fail('KEY_ID_MISMATCH', "credential ID doesn't match keyId");

  return {
    keyId: input.keyId,
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    signCount: 0,
    environment,
    receipt: receipt.toString('base64'),
  };
}

/**
 * Verifies a per-request App Attest assertion against a previously attested
 * key. Persist the returned `signCount`; a counter that doesn't increase
 * indicates a replayed or cloned assertion and is rejected.
 */
export function verifyAppAttestAssertion(input: AppAttestAssertionInput): VerifiedAppAttestAssertion {
  const object = decodeCbor(Buffer.from(input.assertion, 'base64'));
  const signature = asBuffer(mapGet(object, 'signature'), 'signature');
  const authenticatorData = asBuffer(mapGet(object, 'authenticatorData'), 'authenticatorData');

  // nonce = SHA256(authenticatorData | SHA256(clientData)); the signature is ECDSA-SHA256 over the nonce.
  const nonce = sha256(authenticatorData, sha256(Buffer.from(input.clientData, 'utf8')));
  const publicKey = createPublicKey(input.publicKeyPem);
  if (!verifySignature('sha256', nonce, publicKey, signature)) {
    fail('SIGNATURE_INVALID', 'assertion signature does not verify');
  }

  const parsed = parseAuthenticatorData(authenticatorData, false);
  if (!parsed.rpIdHash.equals(sha256(Buffer.from(input.appId, 'utf8')))) {
    fail('APP_ID_MISMATCH', `assertion is not for app ${input.appId}`);
  }
  if (parsed.signCount <= input.previousSignCount) {
    fail('COUNTER_REPLAY', `counter ${parsed.signCount} did not increase past ${input.previousSignCount}`);
  }
  return { signCount: parsed.signCount };
}
