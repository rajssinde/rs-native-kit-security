import { describe, expect, it } from '@jest/globals';
// Explicit `.ts` extension bypasses RN/Metro's `.native.ts` platform-extension
// resolution so this test targets the web/default fallback implementation
// directly, regardless of the Jest preset's default platform.

const {
  getNativeSecurity,
  isNativeSecuritySupported,
} = require('../specs/nativeSecurity.ts');

describe('nativeSecurity web/default fallback', () => {
  it('reports itself as unsupported', () => {
    expect(isNativeSecuritySupported).toBe(false);
  });

  it('every method throws SecurityUnsupportedPlatformError instead of silently reporting "secure"', async () => {
    const native = getNativeSecurity();

    await expect(native.checkRoot()).rejects.toThrow(
      'checkRoot" is not supported on this platform'
    );
    await expect(native.checkSignature([])).rejects.toThrow('checkSignature');
    await expect(native.getSigningIdentity()).rejects.toThrow(
      'getSigningIdentity'
    );
    await expect(native.scan({ expectedSigners: [] })).rejects.toThrow('scan');
    expect(() => native.setEventListener(() => {})).toThrow('setEventListener');
    expect(() => native.startMonitoring()).toThrow('startMonitoring');
    expect(() => native.stopMonitoring()).toThrow('stopMonitoring');
    expect(() => native.removeEventListener()).toThrow('removeEventListener');
  });

  it('implements the base HybridObject members without throwing', () => {
    const native = getNativeSecurity();
    expect(native.name).toBe('Security');
    expect(native.toString()).toContain('Security');
    expect(native.equals(native)).toBe(true);
    expect(() => native.dispose()).not.toThrow();
  });
});
