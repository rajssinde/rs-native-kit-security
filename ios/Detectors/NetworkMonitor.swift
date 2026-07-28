import Foundation

final class NetworkMonitor {

  /// Scans active network interfaces for VPN tunnel prefixes
  /// (`utun`/`ppp`/`ipsec`/`tap`). Avoids requiring the `NetworkExtension`
  /// entitlement that `NEVPNManager` needs, so this works for every app,
  /// not just ones that ship their own VPN configuration.
  func isVpnConnected() -> Bool {
    var addresses: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&addresses) == 0, let firstAddr = addresses else { return false }
    defer { freeifaddrs(addresses) }

    var pointer: UnsafeMutablePointer<ifaddrs>? = firstAddr
    let vpnPrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]

    while let current = pointer {
      let name = String(cString: current.pointee.ifa_name)
      let isUp = (Int32(current.pointee.ifa_flags) & IFF_UP) == IFF_UP
      if isUp && vpnPrefixes.contains(where: { name.hasPrefix($0) }) {
        return true
      }
      pointer = current.pointee.ifa_next
    }
    return false
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
