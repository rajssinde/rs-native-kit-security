import Foundation

final class NetworkMonitor {

  private let vpnInterfacePrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]

  private func systemProxySettings() throws -> [String: Any] {
    guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
      throw DetectionError("CFNetworkCopySystemProxySettings returned no settings")
    }
    return settings
  }

  /// Checks the per-interface (`__SCOPED__`) entries of the system network
  /// settings for a tunnel interface. Scanning `getifaddrs()` instead is wrong
  /// on real devices: iOS always keeps several `utun` interfaces up for
  /// system services (iCloud Private Relay, Continuity, ...), so every
  /// iPhone looked VPN-connected. `__SCOPED__` only lists interfaces that
  /// carry a configured network service, which a tunnel has only while a
  /// VPN is active. Needs no `NetworkExtension` entitlement.
  func checkVpn() -> NativeDetectionResult {
    Detection.run { d in
      d.signal("VPN_SCOPED_INTERFACE", .high) {
        guard let scoped = try systemProxySettings()["__SCOPED__"] as? [String: Any] else { return false }
        return scoped.keys.contains { name in vpnInterfacePrefixes.contains { name.hasPrefix($0) } }
      }
    }
  }

  func checkProxy() -> NativeDetectionResult {
    Detection.run { d in
      let settings = try systemProxySettings()
      d.signal("HTTP_PROXY", .high) { (settings[kCFNetworkProxiesHTTPEnable as String] as? Int) == 1 }
      d.signal("HTTPS_PROXY", .high) { (settings["HTTPSEnable"] as? Int) == 1 }
      // Proxy auto-config (PAC) can route traffic through a proxy just as well.
      d.signal("PAC_PROXY", .medium) { (settings[kCFNetworkProxiesProxyAutoConfigEnable as String] as? Int) == 1 }
    }
  }

  func isVpnConnected() -> Bool { checkVpn().isDetected }
  func isProxyEnabled() -> Bool { checkProxy().isDetected }
}
