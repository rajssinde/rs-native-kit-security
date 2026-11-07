import { getNativeSecurity } from '../specs/nativeSecurity';
import { SecurityConfigError, type CertificatePin } from '../types';
import { isValidPinSet } from './pinning';

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
/** Lowercase DNS hostname with at least two labels; no scheme, port, path or wildcard. */
const HOSTNAME_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})+$`);

export interface SslPinningOptions {
  /** Also pin every subdomain of each hostname. Default `false`. */
  includeSubdomains?: boolean;
  now?: number;
}

let enabled = false;

/**
 * Enforces public-key (SPKI) pinning on the app's React Native networking:
 * every `fetch`/`XMLHttpRequest` to a pinned host fails unless the server's
 * certificate chain contains one of its pins. Android: OkHttp
 * `CertificatePinner` on RN's networking client. iOS: TrustKit (also covers
 * other `NSURLSession` traffic).
 *
 * - Call **once, at startup, before the first network request**: RN builds
 *   its networking client once, and TrustKit can only be initialised once.
 * - Each host needs **at least two pins** — the live key plus a backup key —
 *   so a key rotation can't lock every user out.
 * - Entries past `expiresAt` are skipped (with a warning), so an app that
 *   wasn't updated in time degrades to normal TLS instead of failing forever.
 *
 * Not covered: WebSockets (Android), and HTTP clients outside React Native's
 * networking stack.
 */
export async function enableSslPinning(
  pinSet: CertificatePin[],
  options: SslPinningOptions = {}
): Promise<void> {
  if (enabled) {
    throw new SecurityConfigError(
      'SSL pinning is already enabled; call enableSslPinning() once at startup'
    );
  }
  if (!isValidPinSet(pinSet) || pinSet.length === 0) {
    throw new SecurityConfigError(
      'enableSslPinning() needs a non-empty array of { hostname, pins: ["sha256/<base64>=", ...] }'
    );
  }

  const now = options.now ?? Date.now();
  const domains = [];
  for (const entry of pinSet) {
    const hostname = entry.hostname.trim().toLowerCase();
    if (!HOSTNAME_RE.test(hostname)) {
      throw new SecurityConfigError(
        `"${entry.hostname}" is not a hostname — use e.g. "api.example.com" (no scheme, port, path or wildcard)`
      );
    }
    const pins = [...new Set(entry.pins)];
    if (pins.length < 2) {
      throw new SecurityConfigError(
        `${hostname} needs at least two distinct pins (the current key and a backup key)`
      );
    }
    if (entry.expiresAt !== undefined && entry.expiresAt < now) {
      console.warn(
        `[@rs-native-kit/security] Pins for ${hostname} expired at ${new Date(entry.expiresAt).toISOString()}; ` +
          'that host is NOT pinned. Ship updated pins.'
      );
      continue;
    }
    domains.push({
      hostname,
      pins: pins.map((pin) => pin.slice('sha256/'.length)),
      includeSubdomains: options.includeSubdomains ?? false,
    });
  }

  if (domains.length === 0) {
    throw new SecurityConfigError(
      'every pinned host has expired pins; nothing would be pinned'
    );
  }

  await getNativeSecurity().enableSslPinning(domains);
  enabled = true;
}

/** Test-only. */
export function resetSslPinningState(): void {
  enabled = false;
}
