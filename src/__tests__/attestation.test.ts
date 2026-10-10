import { describe, expect, it, jest } from '@jest/globals';
import { createMockNativeSecurity } from '../__fixtures__/nativeSecurity';

const mockNativeSecurity = createMockNativeSecurity();

jest.mock('../specs/nativeSecurity', () => ({
  isNativeSecuritySupported: true,
  getNativeSecurity: () => mockNativeSecurity,
}));

const attestation = require('../attestation');

describe('attestation', () => {
  it('passes the cloud project number and request data through to Play Integrity', async () => {
    await attestation.prepareIntegrityToken(123456789012);
    expect(mockNativeSecurity.prepareIntegrityToken).toHaveBeenCalledWith(
      123456789012
    );

    await expect(
      attestation.requestIntegrityToken('challenge|POST /transfer')
    ).resolves.toBe('integrity-token');
    expect(mockNativeSecurity.requestIntegrityToken).toHaveBeenCalledWith(
      'challenge|POST /transfer'
    );
  });

  it('rejects an invalid cloud project number before reaching native', async () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      await expect(attestation.prepareIntegrityToken(bad)).rejects.toThrow(
        RangeError
      );
    }
    expect(mockNativeSecurity.prepareIntegrityToken).toHaveBeenCalledTimes(1);
  });

  it('delegates the App Attest flow', async () => {
    await expect(attestation.isAppAttestSupported()).resolves.toBe(true);
    await expect(attestation.generateAppAttestKey()).resolves.toBe('key-id');
    await expect(
      attestation.attestAppAttestKey('key-id', 'challenge')
    ).resolves.toBe('attestation');
    expect(mockNativeSecurity.attestAppAttestKey).toHaveBeenCalledWith(
      'key-id',
      'challenge'
    );
    await expect(
      attestation.generateAppAttestAssertion('key-id', 'data')
    ).resolves.toBe('assertion');
    expect(mockNativeSecurity.generateAppAttestAssertion).toHaveBeenCalledWith(
      'key-id',
      'data'
    );
  });
});

describe('protection', () => {
  const protection = require('../protection');

  it('passes the enabled flag through and resolves whether protection is active', async () => {
    await expect(protection.setScreenCaptureProtection(true)).resolves.toBe(
      true
    );
    expect(mockNativeSecurity.setScreenCaptureProtection).toHaveBeenCalledWith(
      true
    );
    await expect(protection.setOverlayProtection(false)).resolves.toBe(true);
    expect(mockNativeSecurity.setOverlayProtection).toHaveBeenCalledWith(false);
  });
});
