import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Android-only: `Settings.canDrawOverlays()` + a running-services heuristic
 * for known overlay/screen-lock-bypass apps. iOS has no equivalent overlay
 * permission model and always resolves `false`.
 */
export function hasOverlayPermission(): Promise<boolean> {
  return getNativeSecurity().hasOverlayPermission();
}
