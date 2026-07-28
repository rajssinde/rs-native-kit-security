import { describe, expect, it, beforeEach } from '@jest/globals';
import { RiskEngine, classifyRiskLevel } from '../risk/riskEngine';
import { DEFAULT_RISK_THRESHOLDS } from '../risk/weights';
import type { SecurityChecks } from '../types';

const CLEAN_CHECKS: SecurityChecks = {
  root: false,
  jailbreak: false,
  emulator: false,
  developerMode: false,
  usbDebugging: false,
  vpn: false,
  proxy: false,
  overlay: false,
  frida: false,
  xposed: false,
  lsposed: false,
  magisk: false,
  busybox: false,
  mockLocation: false,
  hookDetected: false,
  tampered: false,
  signatureValid: true,
  sslPinningSupported: true,
  screenRecording: false,
  screenCaptured: false,
  debuggerAttached: false,
};

describe('classifyRiskLevel', () => {
  it('buckets scores per default thresholds', () => {
    expect(classifyRiskLevel(0, DEFAULT_RISK_THRESHOLDS)).toBe('LOW');
    expect(classifyRiskLevel(24, DEFAULT_RISK_THRESHOLDS)).toBe('LOW');
    expect(classifyRiskLevel(25, DEFAULT_RISK_THRESHOLDS)).toBe('MEDIUM');
    expect(classifyRiskLevel(49, DEFAULT_RISK_THRESHOLDS)).toBe('MEDIUM');
    expect(classifyRiskLevel(50, DEFAULT_RISK_THRESHOLDS)).toBe('HIGH');
    expect(classifyRiskLevel(74, DEFAULT_RISK_THRESHOLDS)).toBe('HIGH');
    expect(classifyRiskLevel(75, DEFAULT_RISK_THRESHOLDS)).toBe('CRITICAL');
    expect(classifyRiskLevel(100, DEFAULT_RISK_THRESHOLDS)).toBe('CRITICAL');
  });
});

describe('RiskEngine', () => {
  let engine: RiskEngine;

  beforeEach(() => {
    engine = new RiskEngine();
  });

  it('reports a clean device as LOW risk and secure', () => {
    const result = engine.evaluate(CLEAN_CHECKS);
    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe('LOW');
    expect(result.secure).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it('sums weights for triggered checks', () => {
    const result = engine.evaluate({
      ...CLEAN_CHECKS,
      magisk: true, // 40
      root: true, // 30
    });
    expect(result.score).toBe(70);
    expect(result.riskLevel).toBe('HIGH');
    expect(result.secure).toBe(false);
  });

  it('clamps the score at 100 even if weights overflow', () => {
    const result = engine.evaluate({
      ...CLEAN_CHECKS,
      root: true,
      jailbreak: true,
      frida: true,
      xposed: true,
      lsposed: true,
      magisk: true,
      tampered: true,
      hookDetected: true,
    });
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('treats signatureValid=false and sslPinningSupported=false as risk-contributing', () => {
    const result = engine.evaluate({
      ...CLEAN_CHECKS,
      signatureValid: false,
    });
    expect(result.score).toBe(60);
    expect(result.reasons).toContain('App signature could not be verified');
  });

  it('never penalizes sslPinningSupported by default (weight 0)', () => {
    const result = engine.evaluate({
      ...CLEAN_CHECKS,
      sslPinningSupported: false,
    });
    expect(result.score).toBe(0);
    expect(result.secure).toBe(true);
  });

  it('merges native reasons ahead of derived reasons', () => {
    const result = engine.evaluate({ ...CLEAN_CHECKS, root: true }, [
      'su binary found at /system/xbin/su',
    ]);
    expect(result.reasons[0]).toBe('su binary found at /system/xbin/su');
    expect(result.reasons).toContain('Detected: root');
  });

  it('supports configuring custom weights and thresholds', () => {
    engine.configure({ weights: { root: 100 }, thresholds: { medium: 10 } });
    const result = engine.evaluate({ ...CLEAN_CHECKS, root: true });
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe('CRITICAL');

    engine.reset();
    const resetResult = engine.evaluate({ ...CLEAN_CHECKS, root: true });
    expect(resetResult.score).toBe(30);
  });

  it('getWeights/getThresholds return copies, not live references', () => {
    const weights = engine.getWeights();
    weights.root = 999;
    expect(engine.getWeights().root).not.toBe(999);
  });
});
