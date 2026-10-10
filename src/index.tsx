import { Platform } from 'react-native';
import { getNativeSecurity } from './specs/nativeSecurity';
import type { NativeSecurityEvent } from './Security.nitro';
import { defaultRiskEngine } from './risk/riskEngine';
import { SecurityEventEmitter } from './utils/eventEmitter';
import { configure, expectedSignersFor, getConfig } from './config';
import { toDetectionResult, isDetected } from './results';
import { describeReason, REASON_DESCRIPTIONS } from './reasons';
import {
  SECURITY_CHECK_KEYS,
  SecurityUnsupportedPlatformError,
  type RiskEngineConfig,
  type SecurityChecks,
  type SecurityEvent,
  type SecurityEventListener,
  type SecurityEventType,
  type SecurityPlatform,
  type SecurityReport,
} from './types';

import { checkRoot, checkMagisk, checkBusyBox } from './root';
import { checkJailbreak } from './jailbreak';
import { checkEmulator } from './emulator';
import {
  checkDeveloperMode,
  checkUsbDebugging,
  checkDebugger,
  checkMockLocation,
} from './developerMode';
import { checkVpn } from './vpn';
import { checkProxy } from './proxy';
import { checkOverlay } from './overlay';
import { checkScreenRecording, checkScreenCapture } from './screen';
import { checkHooks, checkFrida, checkXposed, checkLSPosed } from './hook';
import { checkTampering, checkApkIntegrity } from './integrity';
import { checkSignature, getSigningIdentity } from './signature';
import {
  prepareIntegrityToken,
  requestIntegrityToken,
  isAppAttestSupported,
  generateAppAttestKey,
  attestAppAttestKey,
  generateAppAttestAssertion,
} from './attestation';
import {
  buildCertificatePin,
  isValidPinFormat,
  isValidPinSet,
  hasExpiredPins,
} from './ssl';

const KNOWN_EVENT_TYPES: ReadonlySet<SecurityEventType> = new Set([
  'ROOT_DETECTED',
  'JAILBREAK_DETECTED',
  'VPN_CONNECTED',
  'PROXY_ENABLED',
  'SCREENSHOT',
  'SCREEN_RECORDING',
  'HOOK_DETECTED',
  'DEBUGGER',
  'TAMPER',
  'SIGNATURE_INVALID',
]);

function resolvePlatform(): SecurityPlatform {
  if (Platform.OS === 'ios') return 'ios';
  if (Platform.OS === 'android') return 'android';
  throw new SecurityUnsupportedPlatformError('scan');
}

/** Unknown native event types are dropped, never remapped to a different threat. */
function toSecurityEvent(event: NativeSecurityEvent): SecurityEvent | null {
  if (!KNOWN_EVENT_TYPES.has(event.type as SecurityEventType)) {
    if (__DEV__) {
      console.warn(
        `[@rs-native-kit/security] Ignoring unknown native event type "${event.type}"`
      );
    }
    return null;
  }
  return {
    type: event.type as SecurityEventType,
    message: event.message,
    timestamp: event.timestamp,
  };
}

/**
 * Full, risk-scored device scan — the primary entry point for most
 * integrations. Runs every check once on a background thread. A check that
 * fails to run is reported in `failed` and makes `secure` false; it is never
 * counted as clean.
 */
export async function scan(): Promise<SecurityReport> {
  const platform = resolvePlatform();
  const timestamp = Date.now();
  const native = await getNativeSecurity().scan({
    expectedSigners: expectedSignersFor(platform),
  });

  const checks = {} as SecurityChecks;
  for (const key of SECURITY_CHECK_KEYS) {
    checks[key] = toDetectionResult(native.checks?.[key]);
  }
  const evaluation = defaultRiskEngine.evaluate(checks);

  return {
    platform,
    secure: evaluation.secure,
    riskLevel: evaluation.riskLevel,
    score: evaluation.score,
    checks,
    detected: evaluation.detected,
    failed: evaluation.failed,
    notConfigured: evaluation.notConfigured,
    complete: evaluation.failed.length === 0,
    reasons: evaluation.reasons,
    durationMs: native.durationMs,
    timestamp,
  };
}

/** Overrides the default risk weights/thresholds/penalty used by `scan()`. Merges with existing config. */
export function configureRiskEngine(config: Partial<RiskEngineConfig>): void {
  defaultRiskEngine.configure(config);
}

/** Resets risk weights/thresholds/penalty to their library defaults. */
export function resetRiskEngine(): void {
  defaultRiskEngine.reset();
}

const emitter = new SecurityEventEmitter();
let monitoringActive = false;

function ensureMonitoring(): void {
  if (monitoringActive) return;
  const native = getNativeSecurity();
  native.setEventListener((event) => {
    const securityEvent = toSecurityEvent(event);
    if (securityEvent) emitter.emit(securityEvent);
  });
  native.startMonitoring();
  monitoringActive = true;
}

function teardownMonitoringIfIdle(): void {
  if (!monitoringActive || emitter.size > 0) return;
  const native = getNativeSecurity();
  native.stopMonitoring();
  native.removeEventListener();
  monitoringActive = false;
}

/**
 * Subscribes to real-time security events (root/jailbreak state changes,
 * VPN/proxy changes, screenshots, screen recording, debugger attach,
 * tamper signals). Returns an unsubscribe function.
 */
export function addListener(listener: SecurityEventListener): () => void {
  ensureMonitoring();
  const unsubscribe = emitter.add(listener);
  return () => {
    unsubscribe();
    teardownMonitoringIfIdle();
  };
}

/** Removes a specific listener previously passed to `addListener()`. */
export function removeListener(listener: SecurityEventListener): void {
  emitter.remove(listener);
  teardownMonitoringIfIdle();
}

/** Removes every registered listener and stops native monitoring. */
export function removeAllListeners(): void {
  emitter.clear();
  teardownMonitoringIfIdle();
}

export {
  configure,
  getConfig,
  checkRoot,
  checkMagisk,
  checkBusyBox,
  checkJailbreak,
  checkEmulator,
  checkDeveloperMode,
  checkUsbDebugging,
  checkDebugger,
  checkMockLocation,
  checkVpn,
  checkProxy,
  checkOverlay,
  checkScreenRecording,
  checkScreenCapture,
  checkHooks,
  checkFrida,
  checkXposed,
  checkLSPosed,
  checkTampering,
  checkApkIntegrity,
  checkSignature,
  getSigningIdentity,
  isDetected,
  describeReason,
  REASON_DESCRIPTIONS,
  prepareIntegrityToken,
  requestIntegrityToken,
  isAppAttestSupported,
  generateAppAttestKey,
  attestAppAttestKey,
  generateAppAttestAssertion,
  buildCertificatePin,
  isValidPinFormat,
  isValidPinSet,
  hasExpiredPins,
};

export * from './types';
export {
  RiskEngine,
  defaultRiskEngine,
  classifyRiskLevel,
  DEFAULT_RISK_WEIGHTS,
  DEFAULT_RISK_THRESHOLDS,
  DEFAULT_FAILED_CHECK_PENALTY,
  RISK_GROUPS,
} from './risk';
export type { RiskEvaluation } from './risk';

const Security = {
  configure,
  getConfig,
  checkRoot,
  checkMagisk,
  checkBusyBox,
  checkJailbreak,
  checkEmulator,
  checkDeveloperMode,
  checkUsbDebugging,
  checkDebugger,
  checkMockLocation,
  checkVpn,
  checkProxy,
  checkOverlay,
  checkScreenRecording,
  checkScreenCapture,
  checkHooks,
  checkFrida,
  checkXposed,
  checkLSPosed,
  checkTampering,
  checkApkIntegrity,
  checkSignature,
  getSigningIdentity,
  isDetected,
  describeReason,
  prepareIntegrityToken,
  requestIntegrityToken,
  isAppAttestSupported,
  generateAppAttestKey,
  attestAppAttestKey,
  generateAppAttestAssertion,
  buildCertificatePin,
  isValidPinFormat,
  isValidPinSet,
  hasExpiredPins,
  scan,
  addListener,
  removeListener,
  removeAllListeners,
  configureRiskEngine,
  resetRiskEngine,
};

export default Security;
