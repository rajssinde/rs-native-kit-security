import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/** Android: JVM and network proxy settings. iOS: HTTP, HTTPS and PAC proxy settings. */
export function checkProxy(): Promise<DetectionResult> {
  return runCheck((native) => native.checkProxy());
}
