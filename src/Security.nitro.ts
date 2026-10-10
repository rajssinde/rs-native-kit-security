import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Outcome of one detector:
 * - `detected`: at least one signal fired — see `reasons`.
 * - `not_detected`: every signal ran and none fired. Never proof of safety:
 *   a capable attacker can hide from on-device checks.
 * - `unsupported`: the concept doesn't exist on this platform (e.g. root on iOS).
 * - `not_configured`: the check needs app-supplied config (e.g. an expected
 *   signature hash) that wasn't provided, so nothing was verified.
 * - `error`: the detector failed to run; its outcome is unknown.
 */
export type NativeDetectionStatus =
  'detected' | 'not_detected' | 'unsupported' | 'not_configured' | 'error';

/**
 * How much the result can be trusted. `detected` takes the strongest fired
 * signal's confidence. `not_detected` is at most `medium` (hiding tools exist)
 * and drops to `low` when some of its signals failed to run.
 */
export type NativeConfidence = 'low' | 'medium' | 'high';

export interface NativeDetectionResult {
  status: NativeDetectionStatus;
  /** Machine-readable reason codes (e.g. `SU_BINARY_FOUND`) for every signal that fired. */
  reasons: string[];
  confidence: NativeConfidence;
  /** Failure details for signals that couldn't run (set for `error`, and for partial failures). */
  error?: string;
}

/** One result per check; keys match `SecurityCheckKey` on the JS side. */
export interface NativeSecurityChecks {
  root: NativeDetectionResult;
  magisk: NativeDetectionResult;
  busybox: NativeDetectionResult;
  jailbreak: NativeDetectionResult;
  emulator: NativeDetectionResult;
  developerMode: NativeDetectionResult;
  usbDebugging: NativeDetectionResult;
  debugger: NativeDetectionResult;
  mockLocation: NativeDetectionResult;
  vpn: NativeDetectionResult;
  proxy: NativeDetectionResult;
  screenRecording: NativeDetectionResult;
  screenCapture: NativeDetectionResult;
  overlay: NativeDetectionResult;
  hooks: NativeDetectionResult;
  frida: NativeDetectionResult;
  xposed: NativeDetectionResult;
  lsposed: NativeDetectionResult;
  tampering: NativeDetectionResult;
  signature: NativeDetectionResult;
}

export interface NativeScanOptions {
  /**
   * Known-good signers for the running platform — Android: signing
   * certificate SHA-256 (hex or base64); iOS: 10-character Team ID. Empty →
   * the `signature` check reports `not_configured`. Several entries support
   * key rotation and per-environment builds.
   */
  expectedSigners: string[];
}

export interface NativeScanResult {
  checks: NativeSecurityChecks;
  durationMs: number;
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
  checkRoot(): Promise<NativeDetectionResult>;
  checkMagisk(): Promise<NativeDetectionResult>;
  checkBusyBox(): Promise<NativeDetectionResult>;

  // --- Jailbreak (iOS) --------------------------------------------------
  checkJailbreak(): Promise<NativeDetectionResult>;

  // --- Emulator / Simulator ----------------------------------------------
  checkEmulator(): Promise<NativeDetectionResult>;

  // --- Developer / debug state --------------------------------------------
  checkDeveloperMode(): Promise<NativeDetectionResult>;
  checkUsbDebugging(): Promise<NativeDetectionResult>;
  checkDebugger(): Promise<NativeDetectionResult>;
  checkMockLocation(): Promise<NativeDetectionResult>;

  // --- Network -------------------------------------------------------------
  checkVpn(): Promise<NativeDetectionResult>;
  checkProxy(): Promise<NativeDetectionResult>;

  // --- Screen ----------------------------------------------------------------
  checkScreenRecording(): Promise<NativeDetectionResult>;
  checkScreenCapture(): Promise<NativeDetectionResult>;

  // --- Overlay (Android) --------------------------------------------------------
  checkOverlay(): Promise<NativeDetectionResult>;

  // --- Hooking frameworks --------------------------------------------------------
  checkHooks(): Promise<NativeDetectionResult>;
  checkFrida(): Promise<NativeDetectionResult>;
  checkXposed(): Promise<NativeDetectionResult>;
  checkLSPosed(): Promise<NativeDetectionResult>;

  // --- Integrity / tamper / signature ----------------------------------------------
  checkTampering(): Promise<NativeDetectionResult>;
  /** `detected` = the app's signer matches none of `expectedSigners` (see `NativeScanOptions`). */
  checkSignature(expectedSigners: string[]): Promise<NativeDetectionResult>;
  /** Android: `detected` = base APK SHA-256 differs from `expectedSha256`. iOS: `unsupported`. */
  checkApkIntegrity(expectedSha256: string): Promise<NativeDetectionResult>;
  /** Android: signing certificate SHA-256 (lowercase hex). iOS: Team ID from the code signature. */
  getSigningIdentity(): Promise<string>;

  // --- Aggregate scan --------------------------------------------------------------
  scan(options: NativeScanOptions): Promise<NativeScanResult>;

  // --- Event system ------------------------------------------------------------------
  setEventListener(listener: (event: NativeSecurityEvent) => void): void;
  removeEventListener(): void;
  startMonitoring(): void;
  stopMonitoring(): void;
}
