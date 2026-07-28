import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Detects Android Emulator/Genymotion/BlueStacks/LDPlayer/Nox/MEmu/generic
 * virtual Android, and the iOS Simulator.
 */
export function isEmulator(): Promise<boolean> {
  return getNativeSecurity().isEmulator();
}
