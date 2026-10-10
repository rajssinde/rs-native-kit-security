import type { NativeDetectionResult } from './Security.nitro';
import type { Confidence, DetectionResult, DetectionStatus } from './types';

const STATUSES: ReadonlySet<DetectionStatus> = new Set([
  'detected',
  'not_detected',
  'unsupported',
  'not_configured',
  'error',
]);

const CONFIDENCES: ReadonlySet<Confidence> = new Set(['low', 'medium', 'high']);

/**
 * Converts a native result to the public shape, defensively: anything
 * malformed becomes an `error` result rather than being trusted, and a
 * `detected` result without reasons is still reported as detected.
 */
export function toDetectionResult(
  native: NativeDetectionResult | undefined
): DetectionResult {
  if (!native || !STATUSES.has(native.status as DetectionStatus)) {
    return {
      status: 'error',
      reasons: [],
      confidence: 'low',
      error: `malformed native result: ${JSON.stringify(native)}`,
    };
  }
  return {
    status: native.status as DetectionStatus,
    reasons: Array.isArray(native.reasons) ? [...native.reasons] : [],
    confidence: CONFIDENCES.has(native.confidence as Confidence)
      ? (native.confidence as Confidence)
      : 'low',
    ...(native.error != null ? { error: native.error } : {}),
  };
}

/** Result for a check that threw instead of resolving (e.g. a rejected native promise). */
export function errorResult(error: unknown): DetectionResult {
  return {
    status: 'error',
    reasons: [],
    confidence: 'low',
    error: error instanceof Error ? error.message : String(error),
  };
}

/** `true` when the result reports a threat. */
export function isDetected(result: DetectionResult): boolean {
  return result.status === 'detected';
}
