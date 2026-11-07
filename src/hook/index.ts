import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/** Umbrella: Frida, plus Xposed/LSPosed/Substrate/Riru (Android) or hooking-framework dylibs (iOS). */
export function checkHooks(): Promise<DetectionResult> {
  return runCheck((native) => native.checkHooks());
}

/** Frida: mapped libraries, threads, injection environment, default listen ports. */
export function checkFrida(): Promise<DetectionResult> {
  return runCheck((native) => native.checkFrida());
}

/** Android: Xposed/EdXposed classes, framework file, manager apps. iOS: `unsupported`. */
export function checkXposed(): Promise<DetectionResult> {
  return runCheck((native) => native.checkXposed());
}

/** Android: LSPosed classes, manager app, files. iOS: `unsupported`. */
export function checkLSPosed(): Promise<DetectionResult> {
  return runCheck((native) => native.checkLSPosed());
}
