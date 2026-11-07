import type {
  Security,
  NativeDetectionResult,
  NativePinnedDomain,
  NativeScanOptions,
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

  checkRoot = (): Promise<NativeDetectionResult> => this.failAsync('checkRoot');
  checkMagisk = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkMagisk');
  checkBusyBox = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkBusyBox');
  checkJailbreak = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkJailbreak');
  checkEmulator = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkEmulator');
  checkDeveloperMode = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkDeveloperMode');
  checkUsbDebugging = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkUsbDebugging');
  checkDebugger = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkDebugger');
  checkMockLocation = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkMockLocation');
  checkVpn = (): Promise<NativeDetectionResult> => this.failAsync('checkVpn');
  checkProxy = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkProxy');
  checkScreenRecording = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkScreenRecording');
  checkScreenCapture = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkScreenCapture');
  checkOverlay = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkOverlay');
  checkHooks = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkHooks');
  checkFrida = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkFrida');
  checkXposed = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkXposed');
  checkLSPosed = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkLSPosed');
  checkTampering = (): Promise<NativeDetectionResult> =>
    this.failAsync('checkTampering');
  checkSignature = (
    _expectedSigners: string[]
  ): Promise<NativeDetectionResult> => this.failAsync('checkSignature');
  checkApkIntegrity = (
    _expectedSha256: string
  ): Promise<NativeDetectionResult> => this.failAsync('checkApkIntegrity');
  getSigningIdentity = (): Promise<string> =>
    this.failAsync('getSigningIdentity');
  setScreenCaptureProtection = (_enabled: boolean): Promise<boolean> =>
    this.failAsync('setScreenCaptureProtection');
  setOverlayProtection = (_enabled: boolean): Promise<boolean> =>
    this.failAsync('setOverlayProtection');
  enableSslPinning = (_domains: NativePinnedDomain[]): Promise<void> =>
    this.failAsync('enableSslPinning');
  prepareIntegrityToken = (_cloudProjectNumber: number): Promise<void> =>
    this.failAsync('prepareIntegrityToken');
  requestIntegrityToken = (_requestData: string): Promise<string> =>
    this.failAsync('requestIntegrityToken');
  requestKeyAttestation = (_challenge: string): Promise<string[]> =>
    this.failAsync('requestKeyAttestation');
  isAppAttestSupported = (): Promise<boolean> =>
    this.failAsync('isAppAttestSupported');
  generateAppAttestKey = (): Promise<string> =>
    this.failAsync('generateAppAttestKey');
  attestAppAttestKey = (_keyId: string, _challenge: string): Promise<string> =>
    this.failAsync('attestAppAttestKey');
  generateAppAttestAssertion = (
    _keyId: string,
    _clientData: string
  ): Promise<string> => this.failAsync('generateAppAttestAssertion');
  scan = (_options: NativeScanOptions): Promise<NativeScanResult> =>
    this.failAsync('scan');

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
