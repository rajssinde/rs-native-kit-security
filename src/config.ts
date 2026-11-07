import {
  SecurityConfigError,
  type SecurityConfig,
  type SecurityPlatform,
} from './types';

const ANDROID_SIGNER_RE =
  /^(?:[0-9a-fA-F]{2}:?){31}[0-9a-fA-F]{2}$|^[A-Za-z0-9+/]{43}=$/;
const IOS_TEAM_ID_RE = /^[A-Z0-9]{10}$/;

let currentConfig: SecurityConfig = {};

function validateSigners(
  platform: SecurityPlatform,
  signers: unknown
): string[] | undefined {
  if (signers === undefined) return undefined;
  if (!Array.isArray(signers)) {
    throw new SecurityConfigError(
      `expectedSigners.${platform} must be an array of strings`
    );
  }
  const pattern = platform === 'android' ? ANDROID_SIGNER_RE : IOS_TEAM_ID_RE;
  const expected =
    platform === 'android'
      ? 'a SHA-256 certificate hash (64 hex chars, optionally ":"-separated, or base64)'
      : 'a 10-character Apple Team ID';
  return signers.map((signer) => {
    if (typeof signer !== 'string' || !pattern.test(signer.trim())) {
      throw new SecurityConfigError(
        `expectedSigners.${platform} contains ${JSON.stringify(signer)}, which is not ${expected}`
      );
    }
    return signer.trim();
  });
}

/**
 * Sets SDK-wide configuration used by `scan()` and the individual checks.
 * Replaces the previous configuration. Throws `SecurityConfigError` on
 * malformed values so a typo can't silently disable a check.
 */
export function configure(config: SecurityConfig): void {
  const android = validateSigners('android', config.expectedSigners?.android);
  const ios = validateSigners('ios', config.expectedSigners?.ios);
  currentConfig = {
    expectedSigners: {
      ...(android ? { android } : {}),
      ...(ios ? { ios } : {}),
    },
  };
}

export function getConfig(): SecurityConfig {
  return currentConfig;
}

export function expectedSignersFor(platform: SecurityPlatform): string[] {
  return [...(currentConfig.expectedSigners?.[platform] ?? [])];
}

/** Test-only: restore defaults. */
export function resetConfig(): void {
  currentConfig = {};
}
