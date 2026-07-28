import { getNativeSecurity } from '../specs/nativeSecurity';
import { timingSafeEqual } from '../utils/validate';

/**
 * Android: SHA-256 of the app's signing certificate. iOS: a digest derived
 * from the embedded provisioning profile / code-signing identity.
 */
export function getAppSignatureHash(): Promise<string> {
  return getNativeSecurity().getAppSignatureHash();
}

/**
 * Verifies the running app's signature against `expectedSignatureHash`
 * (hex or base64, matching whatever `getAppSignatureHash()` returns for the
 * target platform). Delegates to native for the primary check, and never
 * trusts a JS-side-only comparison as the sole guard against tampering.
 */
export async function verifyAppSignature(
  expectedSignatureHash: string
): Promise<boolean> {
  return getNativeSecurity().verifyAppSignature(expectedSignatureHash);
}

/**
 * Convenience helper: fetches the current signature hash and compares it to
 * `expectedSignatureHash` using a timing-safe comparison. Prefer
 * `verifyAppSignature()` for the authoritative native-verified result — use
 * this only when you need the raw hash value too.
 */
export async function compareAppSignature(
  expectedSignatureHash: string
): Promise<{ matches: boolean; actual: string }> {
  const actual = await getAppSignatureHash();
  return { matches: timingSafeEqual(actual, expectedSignatureHash), actual };
}
