import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Zero-config tamper heuristic, evaluated on release builds only (always
 * `false` in debug builds). Android: `FLAG_DEBUGGABLE` set, or no installer
 * package recorded (sideloaded). iOS: development-signing `get-task-allow`
 * entitlement present (re-signed with a development profile). Does not catch
 * a repackaged app re-signed for distribution — use `verifyAppSignature()`.
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
