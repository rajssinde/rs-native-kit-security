import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/**
 * Android: emulator build fingerprints, QEMU files, emulator platform apps
 * (Genymotion, BlueStacks, Nox, MEmu, LDPlayer), telephony placeholders.
 * iOS: the Simulator.
 */
export function checkEmulator(): Promise<DetectionResult> {
  return runCheck((native) => native.checkEmulator());
}
