import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/**
 * iOS: jailbreak file scan, Cydia URL scheme, sandbox-escape write test,
 * tweak-injector dylibs, process-spawn probe, `DYLD_INSERT_LIBRARIES`.
 * Android: `unsupported`.
 */
export function checkJailbreak(): Promise<DetectionResult> {
  return runCheck((native) => native.checkJailbreak());
}
