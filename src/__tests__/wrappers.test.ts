import { describe, expect, it, jest } from '@jest/globals';
import type { Security as NativeSecuritySpec } from '../Security.nitro';

type MockNativeSecurity = {
  [K in keyof NativeSecuritySpec]: NativeSecuritySpec[K] extends (
    ...args: infer A
  ) => infer R
    ? jest.Mock<(...args: A) => R>
    : NativeSecuritySpec[K];
};

const mockNativeSecurity: MockNativeSecurity = {
  name: 'Security',
  toString: jest.fn(),
  equals: jest.fn(),
  dispose: jest.fn(),
  isRooted: jest.fn(async () => true),
  isMagiskDetected: jest.fn(async () => true),
  isBusyBoxDetected: jest.fn(async () => true),
  isJailbroken: jest.fn(async () => true),
  isEmulator: jest.fn(async () => true),
  isDeveloperModeEnabled: jest.fn(async () => true),
  isUsbDebuggingEnabled: jest.fn(async () => true),
  isDebuggerAttached: jest.fn(async () => true),
  isMockLocationEnabled: jest.fn(async () => true),
  isVpnConnected: jest.fn(async () => true),
  isProxyEnabled: jest.fn(async () => true),
  isScreenRecording: jest.fn(async () => true),
  isScreenCaptured: jest.fn(async () => true),
  hasOverlayPermission: jest.fn(async () => true),
  isHookDetected: jest.fn(async () => true),
  isFridaDetected: jest.fn(async () => true),
  isXposedDetected: jest.fn(async () => true),
  isLSPosedDetected: jest.fn(async () => true),
  isTampered: jest.fn(async () => true),
  getAppSignatureHash: jest.fn(async () => 'deadbeef'),
  verifyAppSignature: jest.fn(async () => true),
  verifyApkIntegrity: jest.fn(async () => true),
  isSslPinningSupported: jest.fn(async () => true),
  scan: jest.fn(),
  setEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  startMonitoring: jest.fn(),
  stopMonitoring: jest.fn(),
};

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
const ssl = require('../ssl');

describe('category wrapper modules delegate to the native HybridObject', () => {
  it('root', async () => {
    await expect(root.isRooted()).resolves.toBe(true);
    expect(mockNativeSecurity.isRooted).toHaveBeenCalledTimes(1);

    await expect(root.isMagiskDetected()).resolves.toBe(true);
    expect(mockNativeSecurity.isMagiskDetected).toHaveBeenCalledTimes(1);

    await expect(root.isBusyBoxDetected()).resolves.toBe(true);
    expect(mockNativeSecurity.isBusyBoxDetected).toHaveBeenCalledTimes(1);
  });

  it('jailbreak', async () => {
    await expect(jailbreak.isJailbroken()).resolves.toBe(true);
    expect(mockNativeSecurity.isJailbroken).toHaveBeenCalledTimes(1);
  });

  it('emulator', async () => {
    await expect(emulator.isEmulator()).resolves.toBe(true);
    expect(mockNativeSecurity.isEmulator).toHaveBeenCalledTimes(1);
  });

  it('developerMode', async () => {
    await expect(developerMode.isDeveloperModeEnabled()).resolves.toBe(true);
    expect(mockNativeSecurity.isDeveloperModeEnabled).toHaveBeenCalledTimes(1);

    await expect(developerMode.isUsbDebuggingEnabled()).resolves.toBe(true);
    expect(mockNativeSecurity.isUsbDebuggingEnabled).toHaveBeenCalledTimes(1);

    await expect(developerMode.isDebuggerAttached()).resolves.toBe(true);
    expect(mockNativeSecurity.isDebuggerAttached).toHaveBeenCalledTimes(1);

    await expect(developerMode.isMockLocationEnabled()).resolves.toBe(true);
    expect(mockNativeSecurity.isMockLocationEnabled).toHaveBeenCalledTimes(1);
  });

  it('vpn', async () => {
    await expect(vpn.isVpnConnected()).resolves.toBe(true);
    expect(mockNativeSecurity.isVpnConnected).toHaveBeenCalledTimes(1);
  });

  it('proxy', async () => {
    await expect(proxy.isProxyEnabled()).resolves.toBe(true);
    expect(mockNativeSecurity.isProxyEnabled).toHaveBeenCalledTimes(1);
  });

  it('overlay', async () => {
    await expect(overlay.hasOverlayPermission()).resolves.toBe(true);
    expect(mockNativeSecurity.hasOverlayPermission).toHaveBeenCalledTimes(1);
  });

  it('screen', async () => {
    await expect(screen.isScreenRecording()).resolves.toBe(true);
    expect(mockNativeSecurity.isScreenRecording).toHaveBeenCalledTimes(1);

    await expect(screen.isScreenCaptured()).resolves.toBe(true);
    expect(mockNativeSecurity.isScreenCaptured).toHaveBeenCalledTimes(1);
  });

  it('hook', async () => {
    await expect(hook.isHookDetected()).resolves.toBe(true);
    expect(mockNativeSecurity.isHookDetected).toHaveBeenCalledTimes(1);

    await expect(hook.isFridaDetected()).resolves.toBe(true);
    expect(mockNativeSecurity.isFridaDetected).toHaveBeenCalledTimes(1);

    await expect(hook.isXposedDetected()).resolves.toBe(true);
    expect(mockNativeSecurity.isXposedDetected).toHaveBeenCalledTimes(1);

    await expect(hook.isLSPosedDetected()).resolves.toBe(true);
    expect(mockNativeSecurity.isLSPosedDetected).toHaveBeenCalledTimes(1);
  });

  it('integrity', async () => {
    await expect(integrity.isTampered()).resolves.toBe(true);
    expect(mockNativeSecurity.isTampered).toHaveBeenCalledTimes(1);

    await expect(integrity.verifyApkIntegrity('abc')).resolves.toBe(true);
    expect(mockNativeSecurity.verifyApkIntegrity).toHaveBeenCalledWith('abc');
  });

  it('signature', async () => {
    await expect(signature.getAppSignatureHash()).resolves.toBe('deadbeef');
    expect(mockNativeSecurity.getAppSignatureHash).toHaveBeenCalledTimes(1);

    await expect(signature.verifyAppSignature('deadbeef')).resolves.toBe(true);
    expect(mockNativeSecurity.verifyAppSignature).toHaveBeenCalledWith(
      'deadbeef'
    );

    const { matches, actual } = await signature.compareAppSignature('deadbeef');
    expect(matches).toBe(true);
    expect(actual).toBe('deadbeef');

    const mismatch = await signature.compareAppSignature('not-the-hash');
    expect(mismatch.matches).toBe(false);
  });

  it('ssl', async () => {
    await expect(ssl.isSslPinningSupported()).resolves.toBe(true);
    expect(mockNativeSecurity.isSslPinningSupported).toHaveBeenCalledTimes(1);
  });
});
