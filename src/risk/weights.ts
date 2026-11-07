import type { RiskThresholds, RiskWeights, SecurityCheckKey } from '../types';

/**
 * Default per-check weights. Values mirror the examples from the product
 * spec (magisk 40, root 30, frida 50, debugger 20, tampering 50, proxy 10,
 * vpn 5) extended to cover every check in `SecurityChecks`. Enterprise
 * consumers can override any subset via `Security.configureRiskEngine()`.
 */
export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  root: 30,
  magisk: 40,
  busybox: 15,
  jailbreak: 30,
  emulator: 25,
  developerMode: 10,
  usbDebugging: 15,
  debugger: 20,
  mockLocation: 15,
  vpn: 5,
  proxy: 10,
  screenRecording: 15,
  screenCapture: 5,
  overlay: 20,
  hooks: 50,
  frida: 50,
  xposed: 45,
  lsposed: 45,
  tampering: 50,
  signature: 60,
};

export const DEFAULT_RISK_THRESHOLDS: RiskThresholds = {
  medium: 25,
  high: 50,
  critical: 75,
};

export const DEFAULT_FAILED_CHECK_PENALTY = 1;

/**
 * Checks that report the same underlying threat. A group contributes only
 * its highest-weighted triggered member: one Frida detection fires both
 * `frida` and the `hooks` umbrella, and Magisk implies root, so summing them
 * would double-count a single finding.
 */
export const RISK_GROUPS: readonly (readonly SecurityCheckKey[])[] = [
  ['hooks', 'frida', 'xposed', 'lsposed'],
  ['root', 'magisk', 'busybox'],
];
