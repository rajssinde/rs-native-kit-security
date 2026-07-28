import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Android: `Proxy.getDefaultHost()`/system proxy properties. iOS:
 * `CFNetworkCopySystemProxySettings`.
 */
export function isProxyEnabled(): Promise<boolean> {
  return getNativeSecurity().isProxyEnabled();
}
