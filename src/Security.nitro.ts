import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Raw, native-side detection results. Intentionally flat/primitive-only so it
 * maps cleanly to Kotlin/Swift structs via nitrogen codegen. The public,
 * ergonomic `SecurityChecks` type (src/types) is derived from this shape on
 * the JS side.
 */
export interface NativeSecurityChecks {
  root: boolean;
  jailbreak: boolean;
  emulator: boolean;
  developerMode: boolean;
  usbDebugging: boolean;
  vpn: boolean;
  proxy: boolean;
  overlay: boolean;
  frida: boolean;
  xposed: boolean;
  lsposed: boolean;
  magisk: boolean;
  busybox: boolean;
  mockLocation: boolean;
  hookDetected: boolean;
  tampered: boolean;
  signatureValid: boolean;
  sslPinningSupported: boolean;
  screenRecording: boolean;
  screenCaptured: boolean;
  debuggerAttached: boolean;
}

export interface NativeScanResult {
  checks: NativeSecurityChecks;
  reasons: string[];
}

/**
 * `type` is intentionally `string` (not a TS union) — nitrogen codegen maps
 * primitives cleanly across the JSI boundary; the JS facade narrows it to
 * `SecurityEventType`.
 */
export interface NativeSecurityEvent {
  type: string;
  message: string;
  timestamp: number;
}

export interface Security extends HybridObject<{
  ios: 'swift';
  android: 'kotlin';
}> {
  // --- Root (Android) -------------------------------------------------
  isRooted(): Promise<boolean>;
  isMagiskDetected(): Promise<boolean>;
  isBusyBoxDetected(): Promise<boolean>;

  // --- Jailbreak (iOS) --------------------------------------------------
  isJailbroken(): Promise<boolean>;

  // --- Emulator / Simulator ----------------------------------------------
  isEmulator(): Promise<boolean>;

  // --- Developer / debug state --------------------------------------------
  isDeveloperModeEnabled(): Promise<boolean>;
  isUsbDebuggingEnabled(): Promise<boolean>;
  isDebuggerAttached(): Promise<boolean>;
  isMockLocationEnabled(): Promise<boolean>;

  // --- Network -------------------------------------------------------------
  isVpnConnected(): Promise<boolean>;
  isProxyEnabled(): Promise<boolean>;

  // --- Screen ----------------------------------------------------------------
  isScreenRecording(): Promise<boolean>;
  isScreenCaptured(): Promise<boolean>;

  // --- Overlay (Android) --------------------------------------------------------
  hasOverlayPermission(): Promise<boolean>;

  // --- Hooking frameworks --------------------------------------------------------
  isHookDetected(): Promise<boolean>;
  isFridaDetected(): Promise<boolean>;
  isXposedDetected(): Promise<boolean>;
  isLSPosedDetected(): Promise<boolean>;

  // --- Integrity / tamper / signature ----------------------------------------------
  isTampered(): Promise<boolean>;
  getAppSignatureHash(): Promise<string>;
  verifyAppSignature(expectedSignatureHash: string): Promise<boolean>;
  verifyApkIntegrity(expectedSha256: string): Promise<boolean>;
  isSslPinningSupported(): Promise<boolean>;

  // --- Aggregate scan --------------------------------------------------------------
  scan(): Promise<NativeScanResult>;

  // --- Event system ------------------------------------------------------------------
  setEventListener(listener: (event: NativeSecurityEvent) => void): void;
  removeEventListener(): void;
  startMonitoring(): void;
  stopMonitoring(): void;
}
