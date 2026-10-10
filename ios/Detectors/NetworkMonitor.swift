import Foundation

final class NetworkMonitor {

  private let vpnInterfacePrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]

  /// Checks the per-interface (`__SCOPED__`) entries of the system network
  /// settings for a tunnel interface. Scanning `getifaddrs()` instead is wrong
  /// on real devices: iOS always keeps several `utun` interfaces up for
  /// system services (iCloud Private Relay, Continuity, ...), so every
  /// iPhone looked VPN-connected. `__SCOPED__` only lists interfaces that
  /// carry a configured network service, which a tunnel has only while a
  /// VPN is active. Needs no `NetworkExtension` entitlement.
  func isVpnConnected() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
          let scoped = settings["__SCOPED__"] as? [String: Any]
    else {
      return false
    }
    return scoped.keys.contains { name in
      vpnInterfacePrefixes.contains { name.hasPrefix($0) }
    }
  }

  func isProxyEnabled() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
      return false
    }

    if let httpEnabled = settings[kCFNetworkProxiesHTTPEnable as String] as? Int, httpEnabled == 1 {
      return true
    }
    if let httpsEnabled = settings["HTTPSEnable"] as? Int, httpsEnabled == 1 {
      return true
    }
    // kCFNetworkProxiesSOCKSEnable is macOS-only; iOS has no public SOCKS proxy key.
    return false
  }
}
