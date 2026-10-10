import { afterEach, describe, expect, it } from '@jest/globals';
import {
  configure,
  expectedSignersFor,
  getConfig,
  resetConfig,
} from '../config';
import { SecurityConfigError } from '../types';

const HEX = 'ab'.repeat(32);
const COLON_HEX = Array(32).fill('AB').join(':');
const BASE64 = 'q'.repeat(43) + '=';

afterEach(() => resetConfig());

describe('configure', () => {
  it('accepts Android cert hashes as hex, colon-separated hex or base64, and iOS Team IDs', () => {
    configure({
      expectedSigners: {
        android: [HEX, COLON_HEX, ` ${BASE64} `],
        ios: ['AB12CD34EF'],
      },
    });
    expect(expectedSignersFor('android')).toEqual([HEX, COLON_HEX, BASE64]);
    expect(expectedSignersFor('ios')).toEqual(['AB12CD34EF']);
  });

  it('rejects malformed signers so a typo cannot silently disable the check', () => {
    expect(() =>
      configure({ expectedSigners: { android: ['your-hash-here'] } })
    ).toThrow(SecurityConfigError);
    expect(() =>
      configure({ expectedSigners: { ios: ['ab12cd34ef'] } })
    ).toThrow(SecurityConfigError);
    expect(() =>
      configure({
        expectedSigners: { ios: 'AB12CD34EF' as unknown as string[] },
      })
    ).toThrow(SecurityConfigError);
  });

  it('a rejected configure() leaves the previous config in place', () => {
    configure({ expectedSigners: { ios: ['AB12CD34EF'] } });
    expect(() => configure({ expectedSigners: { ios: ['bad'] } })).toThrow();
    expect(expectedSignersFor('ios')).toEqual(['AB12CD34EF']);
  });

  it('replaces the previous configuration and returns copies', () => {
    configure({ expectedSigners: { ios: ['AB12CD34EF'] } });
    configure({ expectedSigners: { android: [HEX] } });
    expect(expectedSignersFor('ios')).toEqual([]);

    expectedSignersFor('android').push('mutated');
    expect(getConfig().expectedSigners?.android).toEqual([HEX]);
  });
});
