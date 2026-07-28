import Foundation
#if canImport(CoreLocation)
import CoreLocation
#endif

final class DeveloperModeDetector {

  /// iOS has no public API for "Developer Mode" the way Android does.
  /// Best-effort proxy: an `embedded.mobileprovision` is bundled with
  /// development/ad-hoc/enterprise builds but never with App Store builds,
  /// so its presence is a reasonable (if imperfect) stand-in.
  func isDeveloperModeEnabled() -> Bool {
    guard let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
      return false
    }
    return FileManager.default.fileExists(atPath: provisioningPath)
  }

  /// USB debugging (ADB) has no iOS equivalent — Xcode uses a paired
  /// lockdown/trust relationship, not a toggleable device setting. Always
  /// `false`; documented as a platform gap rather than silently omitted.
  func isUsbDebuggingEnabled() -> Bool {
    return false
  }

  /// The classic Apple-documented `sysctl(KERN_PROC)` technique
  /// (Technical Q&A QA1361): inspect this process's own `kinfo_proc` and
  /// check the `P_TRACED` flag.
  func isDebuggerAttached() -> Bool {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

    let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
    guard result == 0 else { return false }

    return (info.kp_proc.p_flag & P_TRACED) != 0
  }

  /// iOS has no direct "mock location provider" concept like Android.
  /// Best-effort: if Core Location has already delivered a location fix
  /// with `sourceInformation.isSimulatedBySoftware` set (iOS 15+), that's a
  /// strong signal; otherwise this conservatively reports `false` rather
  /// than requesting location permission just to check.
  func isMockLocationEnabled() -> Bool {
    #if canImport(CoreLocation) && os(iOS)
    guard #available(iOS 15.0, *) else { return false }
    guard CLLocationManager().authorizationStatus == .authorizedWhenInUse
      || CLLocationManager().authorizationStatus == .authorizedAlways else {
      return false
    }
    return CLLocationManager().location?.sourceInformation?.isSimulatedBySoftware ?? false
    #else
    return false
    #endif
  }
}
