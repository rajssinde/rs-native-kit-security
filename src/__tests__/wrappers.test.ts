import { describe, expect, it, jest } from '@jest/globals';
import {
  createMockNativeSecurity,
  detected,
} from '../__fixtures__/nativeSecurity';

const mockNativeSecurity = createMockNativeSecurity(detected('TEST_SIGNAL'));

jest.mock('../specs/nativeSecurity', () => ({
  isNativeSecuritySupported: true,
  getNativeSecurity: () => mockNativeSecurity,
}));

const root = require('../root');
const jailbreak = require('../jailbreak');
const emulator = require('../emulator');
const developerMode = require('../developerMode');
const vpn = require('../vpn');
const proxy = require('../proxy');
const overlay = require('../overlay');
const screen = require('../screen');
const hook = require('../hook');
const integrity = require('../integrity');
const signature = require('../signature');

const EXPECTED = {
  status: 'detected',
  reasons: ['TEST_SIGNAL'],
  confidence: 'high',
};

/** [module, exported function, native method] for every no-argument check. */
const CHECKS: [
  Record<string, () => Promise<unknown>>,
  string,
  keyof typeof mockNativeSecurity,
][] = [
  [root, 'checkRoot', 'checkRoot'],
  [root, 'checkMagisk', 'checkMagisk'],
  [root, 'checkBusyBox', 'checkBusyBox'],
  [jailbreak, 'checkJailbreak', 'checkJailbreak'],
  [emulator, 'checkEmulator', 'checkEmulator'],
  [developerMode, 'checkDeveloperMode', 'checkDeveloperMode'],
  [developerMode, 'checkUsbDebugging', 'checkUsbDebugging'],
  [developerMode, 'checkDebugger', 'checkDebugger'],
  [developerMode, 'checkMockLocation', 'checkMockLocation'],
  [vpn, 'checkVpn', 'checkVpn'],
  [proxy, 'checkProxy', 'checkProxy'],
  [overlay, 'checkOverlay', 'checkOverlay'],
  [screen, 'checkScreenRecording', 'checkScreenRecording'],
  [screen, 'checkScreenCapture', 'checkScreenCapture'],
  [hook, 'checkHooks', 'checkHooks'],
  [hook, 'checkFrida', 'checkFrida'],
  [hook, 'checkXposed', 'checkXposed'],
  [hook, 'checkLSPosed', 'checkLSPosed'],
  [integrity, 'checkTampering', 'checkTampering'],
];

describe('category wrapper modules delegate to the native HybridObject', () => {
  it.each(CHECKS)('%#: %s', async (module, exportName, nativeMethod) => {
    const fn = module[exportName];
    expect(fn).toBeDefined();
    await expect(fn!()).resolves.toEqual(EXPECTED);
    expect(mockNativeSecurity[nativeMethod]).toHaveBeenCalled();
  });

  it('integrity.checkApkIntegrity passes the expected hash through', async () => {
    await expect(integrity.checkApkIntegrity('abc')).resolves.toEqual(EXPECTED);
    expect(mockNativeSecurity.checkApkIntegrity).toHaveBeenCalledWith('abc');
  });

  it('signature.getSigningIdentity resolves the native identity', async () => {
    await expect(signature.getSigningIdentity()).resolves.toBe('deadbeef');
  });

  it('propagates a rejected native call instead of reporting a result', async () => {
    mockNativeSecurity.checkVpn.mockRejectedValueOnce(
      new Error('unsupported platform')
    );
    await expect(vpn.checkVpn()).rejects.toThrow('unsupported platform');
  });
});
