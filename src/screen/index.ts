import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/**
 * iOS: `UIScreen.isCaptured` (recording, mirroring, AirPlay) — accurate.
 * Android: presentation-display heuristic only (low confidence).
 */
export function checkScreenRecording(): Promise<DetectionResult> {
  return runCheck((native) => native.checkScreenRecording());
}

/**
 * "Was a screenshot taken in the last ~5 seconds". Screenshots are only
 * observed while monitoring runs (an `addListener()` subscription is active);
 * without it the result is `not_detected` with `low` confidence.
 */
export function checkScreenCapture(): Promise<DetectionResult> {
  return runCheck((native) => native.checkScreenCapture());
}
