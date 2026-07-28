import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Umbrella tamper heuristic: signature mismatch, unexpected installer
 * package, debuggable flag on a release build, or a repackaging signal.
 */
export function isTampered(): Promise<boolean> {
  return getNativeSecurity().isTampered();
}

/**
 * Android: compares the running APK's SHA-256 against `expectedSha256`.
 * iOS has no APK equivalent and always resolves `true` (not applicable).
 */
export function verifyApkIntegrity(expectedSha256: string): Promise<boolean> {
  return getNativeSecurity().verifyApkIntegrity(expectedSha256);
}
