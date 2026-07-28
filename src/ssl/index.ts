import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Reports whether the platform's TLS stack supports certificate/public-key
 * pinning (effectively always `true` on Android/iOS). Use the helpers below
 * to build and validate the pin configuration you pass to your networking
 * layer — this SDK does not intercept network traffic itself.
 */
export function isSslPinningSupported(): Promise<boolean> {
  return getNativeSecurity().isSslPinningSupported();
}

export {
  buildCertificatePin,
  isValidPinFormat,
  isValidPinSet,
  hasExpiredPins,
} from './pinning';
