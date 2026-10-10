import { describe, expect, it } from '@jest/globals';
import { errorResult, isDetected, toDetectionResult } from '../results';
import type { NativeDetectionResult } from '../Security.nitro';

describe('toDetectionResult', () => {
  it('passes a well-formed result through, dropping an absent error', () => {
    expect(
      toDetectionResult({
        status: 'detected',
        reasons: ['A'],
        confidence: 'high',
      })
    ).toEqual({
      status: 'detected',
      reasons: ['A'],
      confidence: 'high',
    });
  });

  it('keeps error details', () => {
    expect(
      toDetectionResult({
        status: 'not_detected',
        reasons: [],
        confidence: 'low',
        error: 'partial',
      }).error
    ).toBe('partial');
  });

  it('turns a missing or malformed result into an error', () => {
    expect(toDetectionResult(undefined).status).toBe('error');
    expect(
      toDetectionResult({
        status: 'nope',
        reasons: [],
        confidence: 'high',
      } as unknown as NativeDetectionResult).status
    ).toBe('error');
  });

  it('never trusts an unknown confidence', () => {
    expect(
      toDetectionResult({
        status: 'not_detected',
        reasons: [],
        confidence: 'certain',
      } as unknown as NativeDetectionResult).confidence
    ).toBe('low');
  });
});

describe('errorResult / isDetected', () => {
  it('wraps thrown values', () => {
    expect(errorResult(new Error('boom'))).toEqual({
      status: 'error',
      reasons: [],
      confidence: 'low',
      error: 'boom',
    });
    expect(errorResult('plain').error).toBe('plain');
  });

  it('isDetected only for detected', () => {
    expect(
      isDetected({ status: 'detected', reasons: ['A'], confidence: 'low' })
    ).toBe(true);
    expect(
      isDetected({ status: 'not_configured', reasons: [], confidence: 'high' })
    ).toBe(false);
  });
});
