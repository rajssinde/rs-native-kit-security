import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/**
 * Android: this app's overlay permission and known overlay-abuse apps (both
 * weak signals). iOS: `unsupported` — iOS has no overlay permission model.
 */
export function checkOverlay(): Promise<DetectionResult> {
  return runCheck((native) => native.checkOverlay());
}
