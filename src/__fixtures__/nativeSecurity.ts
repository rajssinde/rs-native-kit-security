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
    setScreenCaptureProtection: jest.fn(async (_e: boolean) => true),
    setOverlayProtection: jest.fn(async (_e: boolean) => true),
    enableSslPinning: jest.fn(async (_d: unknown) => undefined),
    prepareIntegrityToken: jest.fn(async (_n: number) => undefined),
    requestIntegrityToken: jest.fn(async (_d: string) => 'integrity-token'),
    requestKeyAttestation: jest.fn(async (_c: string) => [
      'leaf',
      'intermediate',
    ]),
    isAppAttestSupported: jest.fn(async () => true),
    generateAppAttestKey: jest.fn(async () => 'key-id'),
    attestAppAttestKey: jest.fn(
      async (_k: string, _c: string) => 'attestation'
    ),
    generateAppAttestAssertion: jest.fn(
      async (_k: string, _c: string) => 'assertion'
    ),
    scan: jest.fn(async (_options) => nativeScan()),
    setEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    startMonitoring: jest.fn(),
    stopMonitoring: jest.fn(),
  } as unknown as MockNativeSecurity;
}
