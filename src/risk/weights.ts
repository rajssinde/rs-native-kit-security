import type { RiskThresholds, RiskWeights } from '../types';

/**
 * Default per-check weights. Values mirror the examples from the product
 * spec (magisk 40, root 30, frida 50, debugger 20, tampering 50, proxy 10,
 * vpn 5) extended to cover every check in `SecurityChecks`. Enterprise
 * consumers can override any subset via `Security.configureRiskEngine()`.
 */
export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  root: 30,
  jailbreak: 30,
  emulator: 25,
  developerMode: 10,
  usbDebugging: 15,
  vpn: 5,
  proxy: 10,
  overlay: 20,
  frida: 50,
  xposed: 45,
  lsposed: 45,
  magisk: 40,
  busybox: 15,
  mockLocation: 15,
  hookDetected: 50,
  tampered: 50,
  signatureValid: 60, // triggered when signature is INVALID (see riskEngine.ts)
  sslPinningSupported: 0, // informational only — never penalizes
  screenRecording: 15,
  screenCaptured: 5,
  debuggerAttached: 20,
};

export const DEFAULT_RISK_THRESHOLDS: RiskThresholds = {
  medium: 25,
  high: 50,
  critical: 75,
};
