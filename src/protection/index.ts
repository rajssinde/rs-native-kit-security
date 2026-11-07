import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Prevents capture of sensitive screens — detection (`checkScreenCapture`,
 * `SCREENSHOT` events) tells you after the fact; this stops it.
 *
 * - Android: `FLAG_SECURE` on every activity until disabled — screenshots and
 *   recordings come out black and the app is blank in the recents switcher.
 * - iOS: there's no API to block screenshots. The app is covered while the
 *   screen is being recorded/mirrored and in the app-switcher snapshot.
 *
 * Resolves whether protection is now active.
 */
export function setScreenCaptureProtection(enabled: boolean): Promise<boolean> {
  return getNativeSecurity().setScreenCaptureProtection(enabled);
}

/**
 * Android: hides other apps' overlay windows while this app is in front
 * (Android 12+) and drops touches that pass through an overlay (all
 * versions), blocking tapjacking. iOS: resolves `false` — iOS has no
 * third-party overlays.
 */
export function setOverlayProtection(enabled: boolean): Promise<boolean> {
  return getNativeSecurity().setOverlayProtection(enabled);
}
