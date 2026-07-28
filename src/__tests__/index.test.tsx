import { describe, expect, it, jest, afterEach } from '@jest/globals';
import type {
  Security as NativeSecuritySpec,
  NativeScanResult,
} from '../Security.nitro';

type MockNativeSecurity = {
  [K in keyof NativeSecuritySpec]: NativeSecuritySpec[K] extends (
    ...args: infer A
  ) => infer R
    ? jest.Mock<(...args: A) => R>
    : NativeSecuritySpec[K];
};

function createMockNativeSecurity(): MockNativeSecurity {
  return {
    name: 'Security',
    toString: jest.fn(() => '[HybridObject Security]'),
    equals: jest.fn(() => false),
    dispose: jest.fn(),
    isRooted: jest.fn(async () => false),
    isMagiskDetected: jest.fn(async () => false),
    isBusyBoxDetected: jest.fn(async () => false),
    isJailbroken: jest.fn(async () => false),
    isEmulator: jest.fn(async () => false),
    isDeveloperModeEnabled: jest.fn(async () => false),
    isUsbDebuggingEnabled: jest.fn(async () => false),
    isDebuggerAttached: jest.fn(async () => false),
    isMockLocationEnabled: jest.fn(async () => false),
    isVpnConnected: jest.fn(async () => false),
    isProxyEnabled: jest.fn(async () => false),
    isScreenRecording: jest.fn(async () => false),
    isScreenCaptured: jest.fn(async () => false),
    hasOverlayPermission: jest.fn(async () => false),
    isHookDetected: jest.fn(async () => false),
    isFridaDetected: jest.fn(async () => false),
    isXposedDetected: jest.fn(async () => false),
    isLSPosedDetected: jest.fn(async () => false),
    isTampered: jest.fn(async () => false),
    getAppSignatureHash: jest.fn(async () => 'abc123'),
    verifyAppSignature: jest.fn(async () => true),
    verifyApkIntegrity: jest.fn(async () => true),
    isSslPinningSupported: jest.fn(async () => true),
    scan: jest.fn<() => Promise<NativeScanResult>>(async () => ({
      checks: {
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
      },
      reasons: [],
    })),
    setEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    startMonitoring: jest.fn(),
    stopMonitoring: jest.fn(),
  } as unknown as MockNativeSecurity;
}

let mockNativeSecurity = createMockNativeSecurity();

jest.mock('../specs/nativeSecurity', () => ({
  isNativeSecuritySupported: true,
  getNativeSecurity: () => mockNativeSecurity,
}));

// Loaded via require() (not a static import) so it resolves *after* the
// jest.mock() call above runs, without relying on babel's jest.mock hoisting
// interacting correctly with top-level await (unsupported by this project's
// CJS-targeted babel/jest transform).

const { default: Security, resetRiskEngine } = require('../index');

afterEach(() => {
  mockNativeSecurity = createMockNativeSecurity();
  resetRiskEngine();
});

describe('Security.scan', () => {
  it('returns a clean, secure report when nothing is detected', async () => {
    const report = await Security.scan();

    expect(report.secure).toBe(true);
    expect(report.riskLevel).toBe('LOW');
    expect(report.score).toBe(0);
    expect(['android', 'ios']).toContain(report.platform);
    expect(typeof report.timestamp).toBe('number');
  });

  it('propagates native reasons and raises the score when checks trigger', async () => {
    mockNativeSecurity.scan.mockResolvedValue({
      checks: {
        root: true,
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
        magisk: true,
        busybox: false,
        mockLocation: false,
        hookDetected: false,
        tampered: false,
        signatureValid: true,
        sslPinningSupported: true,
        screenRecording: false,
        screenCaptured: false,
        debuggerAttached: false,
      },
      reasons: ['su binary found at /system/xbin/su'],
    });

    const report = await Security.scan();

    expect(report.score).toBe(70); // root(30) + magisk(40)
    expect(report.riskLevel).toBe('HIGH');
    expect(report.secure).toBe(false);
    expect(report.reasons).toContain('su binary found at /system/xbin/su');
    expect(report.checks.root).toBe(true);
  });
});

describe('Security.configureRiskEngine', () => {
  it('changes scoring used by subsequent scan() calls', async () => {
    mockNativeSecurity.scan.mockResolvedValue({
      checks: {
        root: true,
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
      },
      reasons: [],
    });

    Security.configureRiskEngine({ weights: { root: 100 } });
    const report = await Security.scan();

    expect(report.score).toBe(100);
    expect(report.riskLevel).toBe('CRITICAL');
  });
});

describe('Security event system', () => {
  it('registers a native listener + starts monitoring on the first addListener call', () => {
    const unsubscribe = Security.addListener(() => {});

    expect(mockNativeSecurity.setEventListener).toHaveBeenCalledTimes(1);
    expect(mockNativeSecurity.startMonitoring).toHaveBeenCalledTimes(1);

    unsubscribe();
  });

  it('does not register a second native listener for additional JS listeners', () => {
    const unsubA = Security.addListener(() => {});
    const unsubB = Security.addListener(() => {});

    expect(mockNativeSecurity.setEventListener).toHaveBeenCalledTimes(1);

    unsubA();
    unsubB();
  });

  it('stops native monitoring once the last listener unsubscribes', () => {
    const unsubscribe = Security.addListener(() => {});
    unsubscribe();

    expect(mockNativeSecurity.stopMonitoring).toHaveBeenCalledTimes(1);
    expect(mockNativeSecurity.removeEventListener).toHaveBeenCalledTimes(1);
  });

  it('fans a single native event out to every registered JS listener', () => {
    const received: unknown[] = [];
    const unsubA = Security.addListener((e: unknown) => received.push(e));
    const unsubB = Security.addListener((e: unknown) => received.push(e));

    const nativeCallback = mockNativeSecurity.setEventListener.mock
      .calls[0]?.[0] as (e: unknown) => void;
    nativeCallback({
      type: 'ROOT_DETECTED',
      message: 'root detected at runtime',
      timestamp: 123,
    });

    expect(received).toHaveLength(2);
    expect(received[0]).toEqual({
      type: 'ROOT_DETECTED',
      message: 'root detected at runtime',
      timestamp: 123,
    });

    unsubA();
    unsubB();
  });

  it('falls back to TAMPER for an unrecognized native event type', () => {
    const received: unknown[] = [];
    const unsubscribe = Security.addListener((e: unknown) => received.push(e));

    const nativeCallback = mockNativeSecurity.setEventListener.mock
      .calls[0]?.[0] as (e: unknown) => void;
    nativeCallback({ type: 'SOMETHING_UNKNOWN', message: 'n/a', timestamp: 1 });

    expect(received).toEqual([
      { type: 'TAMPER', message: 'n/a', timestamp: 1 },
    ]);
    unsubscribe();
  });

  it('removeAllListeners tears down monitoring for every listener at once', () => {
    Security.addListener(() => {});
    Security.addListener(() => {});

    Security.removeAllListeners();

    expect(mockNativeSecurity.stopMonitoring).toHaveBeenCalledTimes(1);
  });

  it('removeListener() detaches a specific listener by reference', () => {
    const listener = () => {};
    Security.addListener(listener);

    Security.removeListener(listener);

    expect(mockNativeSecurity.stopMonitoring).toHaveBeenCalledTimes(1);
  });

  it('removeListener() keeps monitoring active while other listeners remain', () => {
    const a = () => {};
    const b = () => {};
    Security.addListener(a);
    Security.addListener(b);

    Security.removeListener(a);

    expect(mockNativeSecurity.stopMonitoring).not.toHaveBeenCalled();

    Security.removeListener(b);
    expect(mockNativeSecurity.stopMonitoring).toHaveBeenCalledTimes(1);
  });
});
