import { jest } from '@jest/globals';
import type {
  NativeDetectionResult,
  NativeScanResult,
  NativeSecurityChecks,
  Security as NativeSecuritySpec,
} from '../Security.nitro';
import { SECURITY_CHECK_KEYS, type SecurityCheckKey } from '../types';

export type MockNativeSecurity = {
  [K in keyof NativeSecuritySpec]: NativeSecuritySpec[K] extends (
    ...args: infer A
  ) => infer R
    ? jest.Mock<(...args: A) => R>
    : NativeSecuritySpec[K];
};

export function result(
  status: NativeDetectionResult['status'] = 'not_detected',
  reasons: string[] = [],
  extra: Partial<NativeDetectionResult> = {}
): NativeDetectionResult {
  return {
    status,
    reasons,
    confidence: status === 'detected' ? 'high' : 'medium',
    ...extra,
  };
}

export const detected = (...reasons: string[]) =>
  result('detected', reasons.length ? reasons : ['TEST_SIGNAL']);

/** Every check `not_detected`, with overrides. */
export function nativeChecks(
  overrides: Partial<Record<SecurityCheckKey, NativeDetectionResult>> = {}
): NativeSecurityChecks {
  const checks = {} as NativeSecurityChecks;
  for (const key of SECURITY_CHECK_KEYS) {
    checks[key] = overrides[key] ?? result();
  }
  return checks;
}

export function nativeScan(
  overrides: Partial<Record<SecurityCheckKey, NativeDetectionResult>> = {}
): NativeScanResult {
  return { checks: nativeChecks(overrides), durationMs: 12 };
}

export function createMockNativeSecurity(
  checkResult: NativeDetectionResult = result()
): MockNativeSecurity {
  const check = () => jest.fn(async () => checkResult);
  return {
    name: 'Security',
    toString: jest.fn(() => '[HybridObject Security]'),
    equals: jest.fn(() => false),
    dispose: jest.fn(),
    checkRoot: check(),
    checkMagisk: check(),
    checkBusyBox: check(),
    checkJailbreak: check(),
    checkEmulator: check(),
    checkDeveloperMode: check(),
    checkUsbDebugging: check(),
    checkDebugger: check(),
    checkMockLocation: check(),
    checkVpn: check(),
    checkProxy: check(),
    checkScreenRecording: check(),
    checkScreenCapture: check(),
    checkOverlay: check(),
    checkHooks: check(),
    checkFrida: check(),
    checkXposed: check(),
    checkLSPosed: check(),
    checkTampering: check(),
    checkSignature: jest.fn(async (_signers: string[]) => checkResult),
    checkApkIntegrity: jest.fn(async (_sha256: string) => checkResult),
    getSigningIdentity: jest.fn(async () => 'deadbeef'),
    scan: jest.fn(async (_options) => nativeScan()),
    setEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    startMonitoring: jest.fn(),
    stopMonitoring: jest.fn(),
  } as unknown as MockNativeSecurity;
}
