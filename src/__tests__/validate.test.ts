import { describe, expect, it } from '@jest/globals';
import {
  isLikelyBase64,
  isLikelyHex,
  timingSafeEqual,
} from '../utils/validate';

describe('isLikelyBase64', () => {
  it('accepts well-formed base64', () => {
    expect(isLikelyBase64('QUJD')).toBe(true);
    expect(isLikelyBase64('QUI=')).toBe(true);
  });

  it('rejects empty strings, odd-length, or invalid characters', () => {
    expect(isLikelyBase64('')).toBe(false);
    expect(isLikelyBase64('QUJ')).toBe(false);
    expect(isLikelyBase64('not base64!!')).toBe(false);
  });
});

describe('isLikelyHex', () => {
  it('accepts well-formed hex', () => {
    expect(isLikelyHex('deadbeef')).toBe(true);
    expect(isLikelyHex('DEADBEEF')).toBe(true);
  });

  it('rejects empty strings, odd-length, or non-hex characters', () => {
    expect(isLikelyHex('')).toBe(false);
    expect(isLikelyHex('abc')).toBe(false);
    expect(isLikelyHex('zzzz')).toBe(false);
  });
});

describe('timingSafeEqual', () => {
  it('returns true for identical strings', () => {
    expect(timingSafeEqual('deadbeef', 'deadbeef')).toBe(true);
  });

  it('returns false for different-length strings', () => {
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
  });

  it('returns false for same-length, different strings', () => {
    expect(timingSafeEqual('deadbeef', 'deadbeee')).toBe(false);
  });

  it('treats empty strings as equal', () => {
    expect(timingSafeEqual('', '')).toBe(true);
  });
});
