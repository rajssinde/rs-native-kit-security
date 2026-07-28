import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Android: `MediaProjection`-adjacent heuristics + display capture flags.
 * iOS: `UIScreen.main.isCaptured`.
 */
export function isScreenRecording(): Promise<boolean> {
  return getNativeSecurity().isScreenRecording();
}

/** Point-in-time "was a screenshot just taken" signal, driven by the event system. */
export function isScreenCaptured(): Promise<boolean> {
  return getNativeSecurity().isScreenCaptured();
}
