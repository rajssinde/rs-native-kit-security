import type {
  Security,
  NativeScanResult,
  NativeSecurityEvent,
} from '../Security.nitro';
import { SecurityUnsupportedPlatformError } from '../types';

/**
 * Web/default fallback used when this package is bundled for a platform
 * Nitro doesn't support (e.g. the example app's `vite`/react-native-web
 * preview build). Every detection method fails loudly instead of silently
 * reporting a false "secure" result — a security SDK must never lie about
 * what it couldn't check.
 *
 * On real Android/iOS builds, Metro's platform-extension resolution picks
 * `nativeSecurity.native.ts` instead of this file.
 */
class UnsupportedSecurity implements Security {
  readonly name = 'Security';

  toString(): string {
    return '[HybridObject Security (unsupported platform)]';
  }

  equals(other: Security): boolean {
    return (other as UnsupportedSecurity) === this;
  }

  dispose(): void {}

  /** For sync (`void`-returning) members — throwing is the only option. */
  private fail(feature: string): never {
    throw new SecurityUnsupportedPlatformError(feature);
  }

  /**
   * For async (`Promise`-returning) members — rejects instead of throwing
   * synchronously, so callers using `.catch()`/`await ... catch` behave the
   * same way they would against the real native implementation.
   */
  private failAsync<T>(feature: string): Promise<T> {
    return Promise.reject(new SecurityUnsupportedPlatformError(feature));
  }

  isRooted(): Promise<boolean> {
    return this.failAsync('isRooted');
  }

  isMagiskDetected(): Promise<boolean> {
    return this.failAsync('isMagiskDetected');
  }

  isBusyBoxDetected(): Promise<boolean> {
    return this.failAsync('isBusyBoxDetected');
  }

  isJailbroken(): Promise<boolean> {
    return this.failAsync('isJailbroken');
  }

  isEmulator(): Promise<boolean> {
    return this.failAsync('isEmulator');
  }

  isDeveloperModeEnabled(): Promise<boolean> {
    return this.failAsync('isDeveloperModeEnabled');
  }

  isUsbDebuggingEnabled(): Promise<boolean> {
    return this.failAsync('isUsbDebuggingEnabled');
  }

  isDebuggerAttached(): Promise<boolean> {
    return this.failAsync('isDebuggerAttached');
  }

  isMockLocationEnabled(): Promise<boolean> {
    return this.failAsync('isMockLocationEnabled');
  }

  isVpnConnected(): Promise<boolean> {
    return this.failAsync('isVpnConnected');
  }

  isProxyEnabled(): Promise<boolean> {
    return this.failAsync('isProxyEnabled');
  }

  isScreenRecording(): Promise<boolean> {
    return this.failAsync('isScreenRecording');
  }

  isScreenCaptured(): Promise<boolean> {
    return this.failAsync('isScreenCaptured');
  }

  hasOverlayPermission(): Promise<boolean> {
    return this.failAsync('hasOverlayPermission');
  }

  isHookDetected(): Promise<boolean> {
    return this.failAsync('isHookDetected');
  }

  isFridaDetected(): Promise<boolean> {
    return this.failAsync('isFridaDetected');
  }

  isXposedDetected(): Promise<boolean> {
    return this.failAsync('isXposedDetected');
  }

  isLSPosedDetected(): Promise<boolean> {
    return this.failAsync('isLSPosedDetected');
  }

  isTampered(): Promise<boolean> {
    return this.failAsync('isTampered');
  }

  getAppSignatureHash(): Promise<string> {
    return this.failAsync('getAppSignatureHash');
  }

  verifyAppSignature(_expectedSignatureHash: string): Promise<boolean> {
    return this.failAsync('verifyAppSignature');
  }

  verifyApkIntegrity(_expectedSha256: string): Promise<boolean> {
    return this.failAsync('verifyApkIntegrity');
  }

  isSslPinningSupported(): Promise<boolean> {
    return this.failAsync('isSslPinningSupported');
  }

  scan(): Promise<NativeScanResult> {
    return this.failAsync('scan');
  }

  setEventListener(_listener: (event: NativeSecurityEvent) => void): void {
    this.fail('setEventListener');
  }

  removeEventListener(): void {
    this.fail('removeEventListener');
  }

  startMonitoring(): void {
    this.fail('startMonitoring');
  }

  stopMonitoring(): void {
    this.fail('stopMonitoring');
  }
}

export const isNativeSecuritySupported = false;

const instance = new UnsupportedSecurity();

export function getNativeSecurity(): Security {
  return instance;
}
