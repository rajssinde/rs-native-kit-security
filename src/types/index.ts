/**
 * Public, platform-agnostic type surface for @rs-native-kit/security.
 * Kept dependency-free from the native/Nitro layer so it can be imported
 * anywhere (including RSC/server contexts, tooling, tests) without pulling
 * in react-native.
 */

export type SecurityPlatform = 'android' | 'ios';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Flat map of every individual detection result. Keys intentionally match
 * the SecurityReport['checks'] shape from the product spec so `scan()` and
 * the individual `isX()` helpers stay consistent.
 */
export interface SecurityChecks {
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

export type SecurityCheckKey = keyof SecurityChecks;

export interface SecurityReport {
  platform: SecurityPlatform;
  secure: boolean;
  riskLevel: RiskLevel;
  score: number;
  checks: SecurityChecks;
  reasons: string[];
  timestamp: number;
}

export type SecurityEventType =
  | 'ROOT_DETECTED'
  | 'JAILBREAK_DETECTED'
  | 'VPN_CONNECTED'
  | 'PROXY_ENABLED'
  | 'SCREENSHOT'
  | 'SCREEN_RECORDING'
  | 'HOOK_DETECTED'
  | 'DEBUGGER'
  | 'TAMPER'
  | 'SIGNATURE_INVALID';

export interface SecurityEvent {
  type: SecurityEventType;
  message: string;
  timestamp: number;
}

export type SecurityEventListener = (event: SecurityEvent) => void;

/** Per-check weight used by the risk engine to derive `score`/`riskLevel`. */
export type RiskWeights = Record<SecurityCheckKey, number>;

export interface RiskThresholds {
  medium: number;
  high: number;
  critical: number;
}

export interface RiskEngineConfig {
  weights: Partial<RiskWeights>;
  thresholds: Partial<RiskThresholds>;
}

/** Thrown by any check invoked on an unsupported platform (e.g. web preview builds). */
export class SecurityUnsupportedPlatformError extends Error {
  constructor(featureName: string) {
    super(
      `[@rs-native-kit/security] "${featureName}" is not supported on this platform. ` +
        'This SDK targets Android and iOS only.'
    );
    this.name = 'SecurityUnsupportedPlatformError';
  }
}

export interface CertificatePin {
  /** Hostname this pin applies to, e.g. "api.example.com". */
  hostname: string;
  /** Base64-encoded SHA-256 hash(es) of the SPKI, e.g. "sha256/AAAA...=". */
  pins: string[];
  /** Optional expiry (unix ms) after which the pin should be treated as stale. */
  expiresAt?: number;
}
