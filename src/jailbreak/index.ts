import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * iOS: canonical suspicious-file scan, Cydia URL scheme, sandbox-escape
 * write test, dylib inspection, fork() probe, suspicious env vars.
 */
export function isJailbroken(): Promise<boolean> {
  return getNativeSecurity().isJailbroken();
}
