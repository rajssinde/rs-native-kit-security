import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/** Android: `su` binary, root-manager apps, build props, SELinux, writable/remounted system partitions. iOS: `unsupported`. */
export function checkRoot(): Promise<DetectionResult> {
  return runCheck((native) => native.checkRoot());
}

/** Android: Magisk app, files, binary and mount-table traces. iOS: `unsupported`. */
export function checkMagisk(): Promise<DetectionResult> {
  return runCheck((native) => native.checkMagisk());
}

/** Android: BusyBox binary presence. iOS: `unsupported`. */
export function checkBusyBox(): Promise<DetectionResult> {
  return runCheck((native) => native.checkBusyBox());
}
