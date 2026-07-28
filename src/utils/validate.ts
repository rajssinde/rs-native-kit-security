const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const HEX_RE = /^[0-9a-fA-F]+$/;

export function isLikelyBase64(value: string): boolean {
  return value.length > 0 && value.length % 4 === 0 && BASE64_RE.test(value);
}

export function isLikelyHex(value: string): boolean {
  return value.length > 0 && value.length % 2 === 0 && HEX_RE.test(value);
}

/**
 * Constant-time-ish string comparison to avoid short-circuit timing leaks
 * when comparing signature/pin hashes. Not a substitute for a real crypto
 * library, but meaningfully better than `===` for this use case.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    // eslint-disable-next-line no-bitwise -- bitwise OR/XOR avoids branching on each char, which is the point of a timing-safe comparison
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
