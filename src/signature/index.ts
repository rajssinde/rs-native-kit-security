import { Platform } from 'react-native';
import { expectedSignersFor } from '../config';
import { getNativeSecurity } from '../specs/nativeSecurity';
import { runCheck } from '../specs/runCheck';
import type { DetectionResult, SecurityPlatform } from '../types';

/**
 * The app's signing identity — Android: SHA-256 of the signing certificate
 * (lowercase hex). iOS: the Team ID from the app's code signature. Log it from
 * a release build to find the value to pass to `configure({ expectedSigners })`.
 */
export function getSigningIdentity(): Promise<string> {
  return getNativeSecurity().getSigningIdentity();
}

/**
 * `detected` when the app's signer matches none of the expected signers —
 * `expectedSigners` if given, otherwise the ones set via `configure()`.
 * `not_configured` when there are none.
 */
export function checkSignature(
  expectedSigners?: string[]
): Promise<DetectionResult> {
  const signers =
    expectedSigners ?? expectedSignersFor(Platform.OS as SecurityPlatform);
  return runCheck((native) => native.checkSignature(signers));
}
