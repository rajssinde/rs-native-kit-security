import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/**
 * Zero-config tamper heuristic, release builds only (`unsupported` with
 * reason `DEBUG_BUILD` in debug builds). Android: debuggable flag, or no
 * installer recorded (sideloaded). iOS: development-signing entitlement.
 * Doesn't catch a repackaged app re-signed for distribution — configure
 * expected signers and use `checkSignature()` for that.
 */
export function checkTampering(): Promise<DetectionResult> {
  return runCheck((native) => native.checkTampering());
}

/**
 * Android: `detected` when the base APK's SHA-256 differs from
 * `expectedSha256`. Only usable for APKs you distribute yourself — Google
 * Play re-signs and splits uploads, so a build-time hash never matches a
 * Play install. iOS: `unsupported`.
 */
export function checkApkIntegrity(
  expectedSha256: string
): Promise<DetectionResult> {
  return runCheck((native) => native.checkApkIntegrity(expectedSha256));
}
