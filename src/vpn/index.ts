import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Android: `ConnectivityManager` VPN transport check. iOS: tunnel interface
 * (`utun`/`ppp`/`ipsec`/...) present in the scoped system network settings.
 */
export function isVpnConnected(): Promise<boolean> {
  return getNativeSecurity().isVpnConnected();
}
