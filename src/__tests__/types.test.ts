import { describe, expect, it } from '@jest/globals';
import { SecurityUnsupportedPlatformError } from '../types';

describe('SecurityUnsupportedPlatformError', () => {
  it('names the offending feature in its message', () => {
    const error = new SecurityUnsupportedPlatformError('isRooted');
    expect(error.name).toBe('SecurityUnsupportedPlatformError');
    expect(error.message).toContain('isRooted');
    expect(error).toBeInstanceOf(Error);
  });
});
