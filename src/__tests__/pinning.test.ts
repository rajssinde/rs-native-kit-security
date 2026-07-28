import { describe, expect, it } from '@jest/globals';
import {
  buildCertificatePin,
  isValidPinFormat,
  isValidPinSet,
  hasExpiredPins,
} from '../ssl/pinning';

const VALID_PIN = `sha256/${'A'.repeat(43)}=`;

describe('isValidPinFormat', () => {
  it('accepts a well-formed sha256 SPKI pin', () => {
    expect(isValidPinFormat(VALID_PIN)).toBe(true);
  });

  it('rejects malformed pins', () => {
    expect(isValidPinFormat('not-a-pin')).toBe(false);
    expect(isValidPinFormat('sha1/AAAA=')).toBe(false);
    expect(isValidPinFormat('sha256/tooshort=')).toBe(false);
  });
});

describe('buildCertificatePin', () => {
  it('builds a pin set for a valid host + pins', () => {
    const pin = buildCertificatePin('api.example.com', [VALID_PIN]);
    expect(pin).toEqual({ hostname: 'api.example.com', pins: [VALID_PIN] });
  });

  it('includes expiresAt when provided', () => {
    const pin = buildCertificatePin('api.example.com', [VALID_PIN], 12345);
    expect(pin.expiresAt).toBe(12345);
  });

  it('throws when no pins are provided', () => {
    expect(() => buildCertificatePin('api.example.com', [])).toThrow();
  });

  it('throws on a malformed pin', () => {
    expect(() => buildCertificatePin('api.example.com', ['bad-pin'])).toThrow();
  });
});

describe('isValidPinSet', () => {
  it('validates a well-formed pin set', () => {
    expect(
      isValidPinSet([{ hostname: 'api.example.com', pins: [VALID_PIN] }])
    ).toBe(true);
  });

  it('rejects non-array input', () => {
    expect(isValidPinSet({})).toBe(false);
    expect(isValidPinSet(null)).toBe(false);
  });

  it('rejects entries with malformed pins', () => {
    expect(
      isValidPinSet([{ hostname: 'api.example.com', pins: ['bad'] }])
    ).toBe(false);
  });

  it('rejects non-object array entries', () => {
    expect(isValidPinSet(['not-an-object', null])).toBe(false);
  });

  it('rejects a non-string hostname or non-array pins field', () => {
    expect(isValidPinSet([{ hostname: 123, pins: [VALID_PIN] }])).toBe(false);
    expect(
      isValidPinSet([{ hostname: 'api.example.com', pins: 'not-an-array' }])
    ).toBe(false);
  });

  it('rejects a non-numeric expiresAt', () => {
    expect(
      isValidPinSet([
        { hostname: 'api.example.com', pins: [VALID_PIN], expiresAt: 'soon' },
      ])
    ).toBe(false);
  });

  it('accepts a valid expiresAt', () => {
    expect(
      isValidPinSet([
        { hostname: 'api.example.com', pins: [VALID_PIN], expiresAt: 12345 },
      ])
    ).toBe(true);
  });
});

describe('hasExpiredPins', () => {
  it('detects expired pins relative to `now`', () => {
    const pinSet = [buildCertificatePin('api.example.com', [VALID_PIN], 1000)];
    expect(hasExpiredPins(pinSet, 2000)).toBe(true);
    expect(hasExpiredPins(pinSet, 500)).toBe(false);
  });

  it('treats pins without expiresAt as never expired', () => {
    const pinSet = [buildCertificatePin('api.example.com', [VALID_PIN])];
    expect(hasExpiredPins(pinSet, Date.now())).toBe(false);
  });
});
