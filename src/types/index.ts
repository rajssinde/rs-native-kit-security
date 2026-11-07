/**
 * Public, platform-agnostic type surface for @rs-native-kit/security.
 * Kept dependency-free from the native/Nitro layer so it can be imported
 * anywhere (including RSC/server contexts, tooling, tests) without pulling
 * in react-native.
 */

export type SecurityPlatform = 'android' | 'ios';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Outcome of one check:
 * - `detected`: at least one signal fired — see `reasons`.
 * - `not_detected`: every signal ran and none fired. Never proof of safety:
 *   a capable attacker can hide from on-device checks.
 * - `unsupported`: the concept doesn't exist on this platform (e.g. root on iOS).
 * - `not_configured`: the check needs app config (e.g. expected signers) that
 *   wasn't provided, so nothing was verified.
 * - `error`: the check failed to run; its outcome is unknown.
 */
export type DetectionStatus =
  'detected' | 'not_detected' | 'unsupported' | 'not_configured' | 'error';

/**
 * How much a result can be trusted. `detected` takes the strongest fired
 * signal's confidence; `not_detected` is at most `medium` (hiding tools
 * exist) and `low` when some of its signals failed to run.
 */
export type Confidence = 'low' | 'medium' | 'high';

export interface DetectionResult {
  status: DetectionStatus;
  /** Reason codes (e.g. `SU_BINARY_FOUND`) — see `describeReason()`. */
  reasons: string[];
  confidence: Confidence;
  /** Why signals failed to run (set for `error`, and for partial failures). */
  error?: string;
}

/** Every check `scan()` runs, in report order. */
export const SECURITY_CHECK_KEYS = [
  'root',
  'magisk',
  'busybox',
  'jailbreak',
  'emulator',
  'developerMode',
  'usbDebugging',
  'debugger',
  'mockLocation',
  'vpn',
  'proxy',
  'screenRecording',
  'screenCapture',
  'overlay',
  'hooks',
  'frida',
  'xposed',
  'lsposed',
  'tampering',
  'signature',
] as const;

export type SecurityCheckKey = (typeof SECURITY_CHECK_KEYS)[number];

/** One result per check. Every check reports a threat as `detected`. */
export type SecurityChecks = Record<SecurityCheckKey, DetectionResult>;

export interface SecurityReport {
  platform: SecurityPlatform;
  /** `true` only when `riskLevel` is `LOW` *and* every check ran (`complete`). */
  secure: boolean;
  riskLevel: RiskLevel;
  /** 0–100. */
  score: number;
  checks: SecurityChecks;
  /** Checks with status `detected`. */
  detected: SecurityCheckKey[];
  /** Checks with status `error` — their outcome is unknown. */
  failed: SecurityCheckKey[];
  /** Checks with status `not_configured` — nothing was verified. */
  notConfigured: SecurityCheckKey[];
  /** `false` when any check failed to run. */
  complete: boolean;
  /** Reason codes of every detected check, de-duplicated. */
  reasons: string[];
  durationMs: number;
  timestamp: number;
}

export interface SecurityConfig {
  /**
   * Known-good signers per platform, checked by `scan()` and
   * `checkSignature()`. Android: signing-certificate SHA-256 (hex, `:`-separated
   * hex, or base64). iOS: Team ID. Several entries support key rotation.
   * Leave unset and the `signature` check reports `not_configured`.
   */
  expectedSigners?: {
    android?: string[];
    ios?: string[];
  };
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
  /**
   * Fraction (0–1) of a check's weight added when that check *failed to run*.
   * Defaults to 1: an unknown result scores like a detection (fail closed).
   */
  failedCheckPenalty: number;
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

/** Thrown when `configure()` receives an invalid value. */
export class SecurityConfigError extends Error {
  constructor(message: string) {
    super(`[@rs-native-kit/security] ${message}`);
    this.name = 'SecurityConfigError';
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
