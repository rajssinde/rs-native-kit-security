import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/** Android: developer options setting. iOS: low-confidence proxy (embedded provisioning profile). */
export function checkDeveloperMode(): Promise<DetectionResult> {
  return runCheck((native) => native.checkDeveloperMode());
}

/** Android: `Settings.Global.ADB_ENABLED`. iOS: `unsupported`. */
export function checkUsbDebugging(): Promise<DetectionResult> {
  return runCheck((native) => native.checkUsbDebugging());
}

/** Android: Java (JDWP) debugger. iOS: `P_TRACED` via `sysctl`. Independent of any JS debugger. */
export function checkDebugger(): Promise<DetectionResult> {
  return runCheck((native) => native.checkDebugger());
}

/**
 * Android: this app selected as mock-location provider; fake-GPS apps installed (weak).
 * iOS: last location fix simulated by software — needs location permission and a fix.
 */
export function checkMockLocation(): Promise<DetectionResult> {
  return runCheck((native) => native.checkMockLocation());
}
