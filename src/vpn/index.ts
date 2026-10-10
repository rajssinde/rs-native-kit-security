import { runCheck } from '../specs/runCheck';
import type { DetectionResult } from '../types';

/**
 * Android: `ConnectivityManager` VPN transport and tunnel interfaces. iOS:
 * tunnel interface (`utun`/`ppp`/`ipsec`/...) in the scoped system network settings.
 */
export function checkVpn(): Promise<DetectionResult> {
  return runCheck((native) => native.checkVpn());
}
