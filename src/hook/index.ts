import { getNativeSecurity } from '../specs/nativeSecurity';

/** Umbrella check: true if Frida, Xposed, LSPosed, EdXposed, Substrate or Riru is detected. */
export function isHookDetected(): Promise<boolean> {
  return getNativeSecurity().isHookDetected();
}

/** Frida server port scan, named pipes, `/proc/self/maps` / loaded-library scan, thread-name scan. */
export function isFridaDetected(): Promise<boolean> {
  return getNativeSecurity().isFridaDetected();
}

/** Android: Xposed/EdXposed class-loader and installer-package presence. */
export function isXposedDetected(): Promise<boolean> {
  return getNativeSecurity().isXposedDetected();
}

/** Android: LSPosed manager package + Zygisk module presence. */
export function isLSPosedDetected(): Promise<boolean> {
  return getNativeSecurity().isLSPosedDetected();
}
