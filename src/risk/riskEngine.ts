import type {
  RiskEngineConfig,
  RiskLevel,
  RiskThresholds,
  RiskWeights,
  SecurityChecks,
  SecurityCheckKey,
} from '../types';
import { DEFAULT_RISK_THRESHOLDS, DEFAULT_RISK_WEIGHTS } from './weights';

/**
 * Checks where `true` means "good"/"safe" — risk is contributed when the
 * value is `false`, unlike every other check (where `true` means "risk
 * detected").
 */
const POSITIVE_CHECKS: ReadonlySet<SecurityCheckKey> = new Set([
  'signatureValid',
  'sslPinningSupported',
]);

export interface RiskEvaluation {
  score: number;
  riskLevel: RiskLevel;
  secure: boolean;
  reasons: string[];
}

function isTriggered(key: SecurityCheckKey, checks: SecurityChecks): boolean {
  const value = checks[key];
  return POSITIVE_CHECKS.has(key) ? value === false : value === true;
}

function describeCheck(key: SecurityCheckKey): string {
  switch (key) {
    case 'signatureValid':
      return 'App signature could not be verified';
    case 'sslPinningSupported':
      return 'SSL pinning is not supported/configured on this device';
    default:
      return `Detected: ${key}`;
  }
}

export function classifyRiskLevel(
  score: number,
  thresholds: RiskThresholds
): RiskLevel {
  if (score >= thresholds.critical) return 'CRITICAL';
  if (score >= thresholds.high) return 'HIGH';
  if (score >= thresholds.medium) return 'MEDIUM';
  return 'LOW';
}

export class RiskEngine {
  private weights: RiskWeights;
  private thresholds: RiskThresholds;

  constructor(config?: Partial<RiskEngineConfig>) {
    this.weights = { ...DEFAULT_RISK_WEIGHTS, ...config?.weights };
    this.thresholds = { ...DEFAULT_RISK_THRESHOLDS, ...config?.thresholds };
  }

  configure(config: Partial<RiskEngineConfig>): void {
    if (config.weights) {
      this.weights = { ...this.weights, ...config.weights };
    }
    if (config.thresholds) {
      this.thresholds = { ...this.thresholds, ...config.thresholds };
    }
  }

  reset(): void {
    this.weights = { ...DEFAULT_RISK_WEIGHTS };
    this.thresholds = { ...DEFAULT_RISK_THRESHOLDS };
  }

  getWeights(): RiskWeights {
    return { ...this.weights };
  }

  getThresholds(): RiskThresholds {
    return { ...this.thresholds };
  }

  evaluate(
    checks: SecurityChecks,
    nativeReasons: string[] = []
  ): RiskEvaluation {
    const reasons: string[] = [...nativeReasons];
    let rawScore = 0;

    for (const key of Object.keys(this.weights) as SecurityCheckKey[]) {
      if (isTriggered(key, checks)) {
        rawScore += this.weights[key];
        reasons.push(describeCheck(key));
      }
    }

    const score = Math.max(0, Math.min(100, rawScore));
    const riskLevel = classifyRiskLevel(score, this.thresholds);
    const secure = riskLevel === 'LOW';

    return { score, riskLevel, secure, reasons };
  }
}

/** Shared default instance used by the top-level `Security` facade. */
export const defaultRiskEngine = new RiskEngine();
