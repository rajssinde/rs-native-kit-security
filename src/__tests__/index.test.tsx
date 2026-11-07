import { describe, expect, it, jest, afterEach } from '@jest/globals';
import {
  createMockNativeSecurity,
  detected,
  nativeScan,
  result,
} from '../__fixtures__/nativeSecurity';

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
const { resetConfig } = require('../config');
const { Platform } = require('react-native');

const ANDROID_CERT = 'a'.repeat(64);

afterEach(() => {
  mockNativeSecurity = createMockNativeSecurity();
  resetRiskEngine();
  resetConfig();
});

describe('Security.scan', () => {
  it('returns a clean, secure, complete report when nothing is detected', async () => {
    const report = await Security.scan();

    expect(report).toMatchObject({
      secure: true,
      complete: true,
      riskLevel: 'LOW',
      score: 0,
      detected: [],
      failed: [],
      reasons: [],
      durationMs: 12,
    });
    expect(['android', 'ios']).toContain(report.platform);
    expect(typeof report.timestamp).toBe('number');
    expect(report.checks.root.status).toBe('not_detected');
  });

  it('reports detections with their reason codes and raises the score', async () => {
    mockNativeSecurity.scan.mockResolvedValue(
      nativeScan({
        emulator: detected('EMULATOR_QEMU_FILES'),
        debugger: detected('JDWP_DEBUGGER_ATTACHED'),
      })
    );

    const report = await Security.scan();

    expect(report.score).toBe(45);
    expect(report.riskLevel).toBe('MEDIUM');
    expect(report.secure).toBe(false);
    expect(report.detected).toEqual(['emulator', 'debugger']);
    expect(report.reasons).toEqual([
      'EMULATOR_QEMU_FILES',
      'JDWP_DEBUGGER_ATTACHED',
    ]);
  });

  it('never reports a failed check as clean', async () => {
    mockNativeSecurity.scan.mockResolvedValue(
      nativeScan({ frida: result('error', [], { error: 'maps unreadable' }) })
    );

    const report = await Security.scan();

    expect(report.complete).toBe(false);
    expect(report.secure).toBe(false);
    expect(report.failed).toEqual(['frida']);
    expect(report.checks.frida.error).toBe('maps unreadable');
  });

  it('treats a malformed native result as an error, not as clean', async () => {
    const scanResult = nativeScan();
    (scanResult.checks as unknown as Record<string, unknown>).root = {
      status: 'probably_fine',
      reasons: [],
      confidence: 'high',
    };
    mockNativeSecurity.scan.mockResolvedValue(scanResult);

    const report = await Security.scan();

    expect(report.checks.root.status).toBe('error');
    expect(report.failed).toContain('root');
  });

  it('passes no expected signers when none are configured, so signature reports not_configured', async () => {
    mockNativeSecurity.scan.mockResolvedValue(
      nativeScan({
        signature: result('not_configured', ['SIGNATURE_HASH_NOT_CONFIGURED']),
      })
    );

    const report = await Security.scan();

    expect(mockNativeSecurity.scan).toHaveBeenCalledWith({
      expectedSigners: [],
    });
    expect(report.notConfigured).toEqual(['signature']);
    expect(report.secure).toBe(true);
  });

  it('passes the configured signers for the running platform', async () => {
    Security.configure({
      expectedSigners: { android: [ANDROID_CERT], ios: ['AB12CD34EF'] },
    });

    await Security.scan();

    expect(mockNativeSecurity.scan).toHaveBeenCalledWith({
      expectedSigners: Platform.OS === 'ios' ? ['AB12CD34EF'] : [ANDROID_CERT],
    });
  });
});

describe('Security.configureRiskEngine', () => {
  it('changes scoring used by subsequent scan() calls', async () => {
    mockNativeSecurity.scan.mockResolvedValue(nativeScan({ root: detected() }));

    Security.configureRiskEngine({ weights: { root: 100 } });
    const report = await Security.scan();

    expect(report.score).toBe(100);
    expect(report.riskLevel).toBe('CRITICAL');
  });
});

describe('individual checks', () => {
  it('return the converted native result', async () => {
    mockNativeSecurity.checkFrida.mockResolvedValue(detected('FRIDA_THREAD'));

    await expect(Security.checkFrida()).resolves.toEqual({
      status: 'detected',
      reasons: ['FRIDA_THREAD'],
      confidence: 'high',
    });
  });

  it('checkSignature() uses the configured signers unless explicit ones are passed', async () => {
    Security.configure({
      expectedSigners: { android: [ANDROID_CERT], ios: ['AB12CD34EF'] },
    });

    await Security.checkSignature();
    expect(mockNativeSecurity.checkSignature).toHaveBeenLastCalledWith(
      Platform.OS === 'ios' ? ['AB12CD34EF'] : [ANDROID_CERT]
    );

    await Security.checkSignature(['ZZ99YY88XX']);
    expect(mockNativeSecurity.checkSignature).toHaveBeenLastCalledWith([
      'ZZ99YY88XX',
    ]);
  });

  it('isDetected() is only true for detected results', () => {
    expect(
      Security.isDetected({
        status: 'detected',
        reasons: ['X'],
        confidence: 'high',
      })
    ).toBe(true);
    expect(
      Security.isDetected({ status: 'error', reasons: [], confidence: 'low' })
    ).toBe(false);
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

  it('drops an unrecognized native event type instead of remapping it to another threat', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const received: unknown[] = [];
    const unsubscribe = Security.addListener((e: unknown) => received.push(e));

    const nativeCallback = mockNativeSecurity.setEventListener.mock
      .calls[0]?.[0] as (e: unknown) => void;
    nativeCallback({ type: 'SOMETHING_UNKNOWN', message: 'n/a', timestamp: 1 });

    expect(received).toEqual([]);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
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
