import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Platform attestation — the signal a compromised device can't fake. These
 * produce opaque tokens for **your server** to verify (see the
 * `@rs-native-kit/security-server` verifier); never make a trust decision on
 * the device. Bind every token to a fresh, single-use server challenge.
 */

/**
 * Android: warms up a Play Integrity Standard token provider. Call once, early
 * (e.g. app start); takes a few seconds. `cloudProjectNumber` is the Google
 * Cloud project number linked in the Play Console. Rejects on iOS.
 */
export function prepareIntegrityToken(
  cloudProjectNumber: number
): Promise<void> {
  if (!Number.isSafeInteger(cloudProjectNumber) || cloudProjectNumber <= 0) {
    return Promise.reject(
      new RangeError(
        `[@rs-native-kit/security] cloudProjectNumber must be a positive integer, got ${cloudProjectNumber}`
      )
    );
  }
  return getNativeSecurity().prepareIntegrityToken(cloudProjectNumber);
}

/**
 * Android: a Play Integrity token bound to `requestData` (its `requestHash`
 * is the hex SHA-256 of `requestData`). Include the server challenge in
 * `requestData`. Rejects on iOS, or if `prepareIntegrityToken()` wasn't called.
 */
export function requestIntegrityToken(requestData: string): Promise<string> {
  return getNativeSecurity().requestIntegrityToken(requestData);
}

/** iOS: whether App Attest is available (iOS 14+ physical device). `false` on Android and in the Simulator. */
export function isAppAttestSupported(): Promise<boolean> {
  return getNativeSecurity().isAppAttestSupported();
}

/** iOS: creates a Secure Enclave key and resolves its `keyId`. Persist it (e.g. Keychain) and reuse it. */
export function generateAppAttestKey(): Promise<string> {
  return getNativeSecurity().generateAppAttestKey();
}

/**
 * iOS: one-time attestation of `keyId`, bound to a server `challenge`
 * (`clientDataHash` = SHA-256 of `challenge`). Send the base64 result and
 * `keyId` to your server, which verifies it and stores the key's public key.
 */
export function attestAppAttestKey(
  keyId: string,
  challenge: string
): Promise<string> {
  return getNativeSecurity().attestAppAttestKey(keyId, challenge);
}

/**
 * iOS: per-request proof from an attested key (`clientDataHash` = SHA-256 of
 * `clientData`). Put the server challenge and the request payload in
 * `clientData`, and send both it and the base64 assertion to your server.
 */
export function generateAppAttestAssertion(
  keyId: string,
  clientData: string
): Promise<string> {
  return getNativeSecurity().generateAppAttestAssertion(keyId, clientData);
}
