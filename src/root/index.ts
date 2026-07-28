import { getNativeSecurity } from '../specs/nativeSecurity';

/** Android: su binary, RW /system, dangerous root apps, build tags, SELinux, mounts, native checks. */
export function isRooted(): Promise<boolean> {
  return getNativeSecurity().isRooted();
}

/** Android: Magisk app, Magisk hide/props, Magisk-managed su. */
export function isMagiskDetected(): Promise<boolean> {
  return getNativeSecurity().isMagiskDetected();
}

/** Android: BusyBox binary presence on PATH. */
export function isBusyBoxDetected(): Promise<boolean> {
  return getNativeSecurity().isBusyBoxDetected();
}
