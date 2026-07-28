import { getNativeSecurity } from '../specs/nativeSecurity';

/**
 * Android: `ConnectivityManager` VPN transport check. iOS: network
 * interface scan for `utun`/`ppp`/`ipsec` tunnel interfaces.
 */
export function isVpnConnected(): Promise<boolean> {
  return getNativeSecurity().isVpnConnected();
}
