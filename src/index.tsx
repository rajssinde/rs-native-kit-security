import { Platform } from 'react-native';
import { getNativeSecurity } from './specs/nativeSecurity';
import type { NativeSecurityEvent } from './Security.nitro';
import { defaultRiskEngine } from './risk/riskEngine';
import { SecurityEventEmitter } from './utils/eventEmitter';
import {
  SecurityUnsupportedPlatformError,
  type RiskEngineConfig,
  type SecurityEvent,
  type SecurityEventListener,
  type SecurityEventType,
  type SecurityPlatform,
  type SecurityReport,
} from './types';

import { isRooted, isMagiskDetected, isBusyBoxDetected } from './root';
import { isJailbroken } from './jailbreak';
import { isEmulator } from './emulator';
import {
  isDeveloperModeEnabled,
  isUsbDebuggingEnabled,
  isDebuggerAttached,
  isMockLocationEnabled,
} from './developerMode';
import { isVpnConnected } from './vpn';
import { isProxyEnabled } from './proxy';
import { hasOverlayPermission } from './overlay';
import { isScreenRecording, isScreenCaptured } from './screen';
import {
  isHookDetected,
  isFridaDetected,
  isXposedDetected,
  isLSPosedDetected,
} from './hook';
import { isTampered, verifyApkIntegrity } from './integrity';
import {
  getAppSignatureHash,
  verifyAppSignature,
  compareAppSignature,
} from './signature';
import {
  isSslPinningSupported,
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

function toSecurityEvent(event: NativeSecurityEvent): SecurityEvent {
  const type = KNOWN_EVENT_TYPES.has(event.type as SecurityEventType)
    ? (event.type as SecurityEventType)
    : 'TAMPER';

  return { type, message: event.message, timestamp: event.timestamp };
}

/** Full, risk-scored device scan — the primary entry point for most integrations. */
export async function scan(): Promise<SecurityReport> {
  const platform = resolvePlatform();
  const { checks, reasons } = await getNativeSecurity().scan();
  const evaluation = defaultRiskEngine.evaluate(checks, reasons);

  return {
    platform,
    secure: evaluation.secure,
    riskLevel: evaluation.riskLevel,
    score: evaluation.score,
    checks,
    reasons: evaluation.reasons,
    timestamp: Date.now(),
  };
}

/** Overrides the default risk weights/thresholds used by `scan()`. Merges with existing config. */
export function configureRiskEngine(config: Partial<RiskEngineConfig>): void {
  defaultRiskEngine.configure(config);
}

/** Resets risk weights/thresholds to their library defaults. */
export function resetRiskEngine(): void {
  defaultRiskEngine.reset();
}

const emitter = new SecurityEventEmitter();
let monitoringActive = false;

function ensureMonitoring(): void {
  if (monitoringActive) return;
  const native = getNativeSecurity();
  native.setEventListener((event) => emitter.emit(toSecurityEvent(event)));
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
 * tamper/signature signals). Returns an unsubscribe function.
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
  isRooted,
  isMagiskDetected,
  isBusyBoxDetected,
  isJailbroken,
  isEmulator,
  isDeveloperModeEnabled,
  isUsbDebuggingEnabled,
  isDebuggerAttached,
  isMockLocationEnabled,
  isVpnConnected,
  isProxyEnabled,
  hasOverlayPermission,
  isScreenRecording,
  isScreenCaptured,
  isHookDetected,
  isFridaDetected,
  isXposedDetected,
  isLSPosedDetected,
  isTampered,
  verifyApkIntegrity,
  getAppSignatureHash,
  verifyAppSignature,
  compareAppSignature,
  isSslPinningSupported,
  buildCertificatePin,
  isValidPinFormat,
  isValidPinSet,
  hasExpiredPins,
};

export * from './types';
export {
  RiskEngine,
  DEFAULT_RISK_WEIGHTS,
  DEFAULT_RISK_THRESHOLDS,
} from './risk';
export type { RiskEvaluation } from './risk';

const Security = {
  isRooted,
  isMagiskDetected,
  isBusyBoxDetected,
  isJailbroken,
  isEmulator,
  isDeveloperModeEnabled,
  isUsbDebuggingEnabled,
  isDebuggerAttached,
  isMockLocationEnabled,
  isVpnConnected,
  isProxyEnabled,
  hasOverlayPermission,
  isScreenRecording,
  isScreenCaptured,
  isHookDetected,
  isFridaDetected,
  isXposedDetected,
  isLSPosedDetected,
  isTampered,
  verifyApkIntegrity,
  getAppSignatureHash,
  verifyAppSignature,
  compareAppSignature,
  isSslPinningSupported,
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
