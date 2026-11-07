import type {
  RiskEngineConfig,
  RiskLevel,
  RiskThresholds,
  RiskWeights,
  SecurityChecks,
  SecurityCheckKey,
} from '../types';
import {
  DEFAULT_FAILED_CHECK_PENALTY,
  DEFAULT_RISK_THRESHOLDS,
  DEFAULT_RISK_WEIGHTS,
  RISK_GROUPS,
} from './weights';

export interface RiskEvaluation {
  score: number;
  riskLevel: RiskLevel;
  /** `riskLevel === 'LOW'` and no check failed to run. */
  secure: boolean;
  detected: SecurityCheckKey[];
  failed: SecurityCheckKey[];
  notConfigured: SecurityCheckKey[];
  /** Reason codes of every detected check, de-duplicated. */
  reasons: string[];
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

const GROUP_OF = new Map<SecurityCheckKey, number>();
RISK_GROUPS.forEach((group, index) =>
  group.forEach((key) => GROUP_OF.set(key, index))
);

export class RiskEngine {
  private weights: RiskWeights;
  private thresholds: RiskThresholds;
  private failedCheckPenalty: number;

  constructor(config?: Partial<RiskEngineConfig>) {
    this.weights = { ...DEFAULT_RISK_WEIGHTS };
    this.thresholds = { ...DEFAULT_RISK_THRESHOLDS };
    this.failedCheckPenalty = DEFAULT_FAILED_CHECK_PENALTY;
    if (config) this.configure(config);
  }

  configure(config: Partial<RiskEngineConfig>): void {
    if (config.weights) {
      this.weights = { ...this.weights, ...config.weights };
    }
    if (config.thresholds) {
      this.thresholds = { ...this.thresholds, ...config.thresholds };
    }
    if (config.failedCheckPenalty !== undefined) {
      const penalty = config.failedCheckPenalty;
      if (!(penalty >= 0 && penalty <= 1)) {
        throw new RangeError(
          `[@rs-native-kit/security] failedCheckPenalty must be between 0 and 1, got ${penalty}`
        );
      }
      this.failedCheckPenalty = penalty;
    }
  }

  reset(): void {
    this.weights = { ...DEFAULT_RISK_WEIGHTS };
    this.thresholds = { ...DEFAULT_RISK_THRESHOLDS };
    this.failedCheckPenalty = DEFAULT_FAILED_CHECK_PENALTY;
  }

  getWeights(): RiskWeights {
    return { ...this.weights };
  }

  getThresholds(): RiskThresholds {
    return { ...this.thresholds };
  }

  getFailedCheckPenalty(): number {
    return this.failedCheckPenalty;
  }

  evaluate(checks: SecurityChecks): RiskEvaluation {
    const detected: SecurityCheckKey[] = [];
    const failed: SecurityCheckKey[] = [];
    const notConfigured: SecurityCheckKey[] = [];
    const reasons = new Set<string>();
    const groupScores = new Map<number, number>();
    let ungroupedScore = 0;

    for (const key of Object.keys(checks) as SecurityCheckKey[]) {
      const result = checks[key];
      let contribution = 0;

      switch (result.status) {
        case 'detected':
          detected.push(key);
          result.reasons.forEach((reason) => reasons.add(reason));
          contribution = this.weights[key] ?? 0;
          break;
        case 'error':
          failed.push(key);
          contribution = (this.weights[key] ?? 0) * this.failedCheckPenalty;
          break;
        case 'not_configured':
          notConfigured.push(key);
          break;
      }

      const group = GROUP_OF.get(key);
      if (group === undefined) {
        ungroupedScore += contribution;
      } else {
        groupScores.set(
          group,
          Math.max(groupScores.get(group) ?? 0, contribution)
        );
      }
    }

    let rawScore = ungroupedScore;
    groupScores.forEach((value) => (rawScore += value));

    const score = Math.round(Math.max(0, Math.min(100, rawScore)));
    const riskLevel = classifyRiskLevel(score, this.thresholds);

    return {
      score,
      riskLevel,
      secure: riskLevel === 'LOW' && failed.length === 0,
      detected,
      failed,
      notConfigured,
      reasons: [...reasons],
    };
  }
}

/** Shared default instance used by the top-level `Security` facade. */
export const defaultRiskEngine = new RiskEngine();
