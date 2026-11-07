import { describe, expect, it, beforeEach } from '@jest/globals';
import { RiskEngine, classifyRiskLevel } from '../risk/riskEngine';
import { DEFAULT_RISK_THRESHOLDS } from '../risk/weights';
import { toDetectionResult } from '../results';
import { SECURITY_CHECK_KEYS, type SecurityChecks } from '../types';
import { detected, nativeChecks, result } from '../__fixtures__/nativeSecurity';

type Overrides = Parameters<typeof nativeChecks>[0];

function checks(overrides: Overrides = {}): SecurityChecks {
  const native = nativeChecks(overrides);
  const out = {} as SecurityChecks;
  for (const key of SECURITY_CHECK_KEYS)
    out[key] = toDetectionResult(native[key]);
  return out;
}

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
    const evaluation = engine.evaluate(checks());
    expect(evaluation).toMatchObject({
      score: 0,
      riskLevel: 'LOW',
      secure: true,
      detected: [],
      failed: [],
      reasons: [],
    });
  });

  it('sums weights of independent detections', () => {
    const evaluation = engine.evaluate(
      checks({ emulator: detected(), debugger: detected() }) // 25 + 20
    );
    expect(evaluation.score).toBe(45);
    expect(evaluation.riskLevel).toBe('MEDIUM');
    expect(evaluation.secure).toBe(false);
    expect(evaluation.detected).toEqual(['emulator', 'debugger']);
  });

  it('counts one finding once when the hooks umbrella and frida both fire', () => {
    const evaluation = engine.evaluate(
      checks({
        frida: detected('FRIDA_THREAD'),
        hooks: detected('FRIDA_THREAD'),
      })
    );
    expect(evaluation.score).toBe(50); // max(frida 50, hooks 50), not 100
    expect(evaluation.reasons).toEqual(['FRIDA_THREAD']);
  });

  it('counts magisk + root as one root-access finding (highest weight wins)', () => {
    const evaluation = engine.evaluate(
      checks({ root: detected(), magisk: detected() })
    );
    expect(evaluation.score).toBe(40);
  });

  it('scores a failed check like a detection by default (fail closed) and marks it not secure', () => {
    const evaluation = engine.evaluate(
      checks({ frida: result('error', [], { error: 'boom' }) })
    );
    expect(evaluation.score).toBe(50);
    expect(evaluation.failed).toEqual(['frida']);
    expect(evaluation.secure).toBe(false);
  });

  it('a failed check makes the report not secure even when its penalty is zero', () => {
    engine.configure({ failedCheckPenalty: 0 });
    const evaluation = engine.evaluate(checks({ vpn: result('error') }));
    expect(evaluation.score).toBe(0);
    expect(evaluation.riskLevel).toBe('LOW');
    expect(evaluation.secure).toBe(false);
  });

  it('applies a partial failedCheckPenalty', () => {
    engine.configure({ failedCheckPenalty: 0.5 });
    expect(engine.evaluate(checks({ tampering: result('error') })).score).toBe(
      25
    );
  });

  it('rejects an out-of-range failedCheckPenalty', () => {
    expect(() => engine.configure({ failedCheckPenalty: 2 })).toThrow(
      RangeError
    );
    expect(() => engine.configure({ failedCheckPenalty: Number.NaN })).toThrow(
      RangeError
    );
  });

  it('never scores unsupported or not_configured checks, but lists not_configured ones', () => {
    const evaluation = engine.evaluate(
      checks({
        jailbreak: result('unsupported'),
        signature: result('not_configured', ['SIGNATURE_HASH_NOT_CONFIGURED']),
      })
    );
    expect(evaluation.score).toBe(0);
    expect(evaluation.secure).toBe(true);
    expect(evaluation.notConfigured).toEqual(['signature']);
    expect(evaluation.reasons).toEqual([]);
  });

  it('a signature mismatch alone is HIGH risk', () => {
    const evaluation = engine.evaluate(
      checks({ signature: detected('SIGNATURE_MISMATCH') })
    );
    expect(evaluation.score).toBe(60);
    expect(evaluation.riskLevel).toBe('HIGH');
  });

  it('clamps the score at 100', () => {
    const evaluation = engine.evaluate(
      checks({
        root: detected(),
        jailbreak: detected(),
        frida: detected(),
        tampering: detected(),
        signature: detected(),
      })
    );
    expect(evaluation.score).toBe(100);
    expect(evaluation.riskLevel).toBe('CRITICAL');
  });

  it('supports configuring custom weights and thresholds, and reset()', () => {
    engine.configure({ weights: { root: 100 }, thresholds: { medium: 10 } });
    const evaluation = engine.evaluate(checks({ root: detected() }));
    expect(evaluation.score).toBe(100);
    expect(evaluation.riskLevel).toBe('CRITICAL');

    engine.reset();
    expect(engine.evaluate(checks({ root: detected() })).score).toBe(30);
    expect(engine.getFailedCheckPenalty()).toBe(1);
  });

  it('getWeights/getThresholds return copies, not live references', () => {
    const weights = engine.getWeights();
    weights.root = 999;
    expect(engine.getWeights().root).not.toBe(999);
  });
});
