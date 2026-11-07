import type { NativeDetectionResult, Security } from '../Security.nitro';
import { toDetectionResult } from '../results';
import type { DetectionResult } from '../types';
import { getNativeSecurity } from './nativeSecurity';

/**
 * Runs one native check and converts its result. A rejected native promise
 * propagates (e.g. `SecurityUnsupportedPlatformError` on web) — callers asked
 * for this specific check, so they should see why it couldn't run. `scan()`
 * is the aggregate path and never throws for a single check.
 */
export async function runCheck(
  call: (native: Security) => Promise<NativeDetectionResult>
): Promise<DetectionResult> {
  return toDetectionResult(await call(getNativeSecurity()));
}
