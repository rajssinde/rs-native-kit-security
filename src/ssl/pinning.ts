import type { CertificatePin } from '../types';
import { isLikelyBase64 } from '../utils/validate';

const SPKI_PIN_RE = /^sha256\/[A-Za-z0-9+/]{43}=$/;

/**
 * Builds a validated `CertificatePin`. This SDK does not perform TLS
 * interception itself (RN networking is owned by the app/OkHttp/
 * NSURLSession) — this is a typed helper for assembling the pin set you
 * hand to `OkHttpClient.Builder#certificatePinner` (Android) or
 * `URLSessionDelegate` / `NSURLSession` server-trust evaluation (iOS).
 *
 * @throws if any pin isn't a well-formed `sha256/<base64-spki-hash>=` value.
 */
export function buildCertificatePin(
  hostname: string,
  pins: string[],
  expiresAt?: number
): CertificatePin {
  if (pins.length === 0) {
    throw new Error(
      `[@rs-native-kit/security] buildCertificatePin("${hostname}") requires at least one pin.`
    );
  }

  for (const pin of pins) {
    if (!SPKI_PIN_RE.test(pin)) {
      throw new Error(
        `[@rs-native-kit/security] Invalid SPKI pin "${pin}" for host "${hostname}". ` +
          'Expected format: "sha256/<base64-encoded SPKI SHA-256 hash>="'
      );
    }
  }

  return { hostname, pins, ...(expiresAt !== undefined ? { expiresAt } : {}) };
}

/** Returns `true` if `pin` looks like a syntactically valid `sha256/...=` SPKI pin. */
export function isValidPinFormat(pin: string): boolean {
  return SPKI_PIN_RE.test(pin);
}

/**
 * Checks whether a `CertificatePin` set contains any expired entries as of
 * `now` (defaults to `Date.now()`). Enterprises should rotate pins before
 * expiry — this is a proactive guard against a fully-expired, unusable pin
 * set silently hard-failing all requests.
 */
export function hasExpiredPins(
  pinSet: readonly CertificatePin[],
  now: number = Date.now()
): boolean {
  return pinSet.some(
    (pin) => pin.expiresAt !== undefined && pin.expiresAt < now
  );
}

/** Basic structural validation for a raw (untrusted/config-loaded) pin set. */
export function isValidPinSet(value: unknown): value is CertificatePin[] {
  if (!Array.isArray(value)) return false;

  return value.every((entry): entry is CertificatePin => {
    if (typeof entry !== 'object' || entry === null) return false;
    const candidate = entry as Record<string, unknown>;
    return (
      typeof candidate.hostname === 'string' &&
      Array.isArray(candidate.pins) &&
      candidate.pins.every(
        (p): p is string => typeof p === 'string' && isValidPinFormat(p)
      ) &&
      (candidate.expiresAt === undefined ||
        typeof candidate.expiresAt === 'number')
    );
  });
}

export { isLikelyBase64 };
