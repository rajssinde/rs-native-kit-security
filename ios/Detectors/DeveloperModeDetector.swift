import Foundation
#if canImport(CoreLocation)
import CoreLocation
#endif

final class DeveloperModeDetector {

  /// iOS has no public API for "Developer Mode" the way Android does.
  /// Best-effort proxy: an `embedded.mobileprovision` is bundled with
  /// development/ad-hoc/enterprise builds but never with App Store builds,
  /// so its presence is a weak (low-confidence) stand-in.
  func checkDeveloperMode() -> NativeDetectionResult {
    Detection.run { d in
      d.signal("EMBEDDED_PROVISIONING_PROFILE", .low) {
        Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") != nil
      }
    }
  }

  /// The classic Apple-documented `sysctl(KERN_PROC)` technique
  /// (Technical Q&A QA1361): inspect this process's own `kinfo_proc` and
  /// check the `P_TRACED` flag.
  func checkDebugger() -> NativeDetectionResult {
    Detection.run { d in
      d.signal("PTRACE_TRACED", .high) { try isDebuggerAttached() }
      #if !targetEnvironment(simulator)
      // Apps launched from the home screen are children of launchd (pid 1);
      // launched by debugserver/Xcode, they're its child instead. Catches a
      // debugger that hid P_TRACED.
      d.signal("PARENT_NOT_LAUNCHD", .medium) { getppid() != 1 }
      #endif
    }
  }

  func isDebuggerAttached() throws -> Bool {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

    guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else {
      throw DetectionError("sysctl(KERN_PROC) failed: errno \(errno)")
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0
  }

  /// iOS has no "mock location provider" setting like Android. If Core
  /// Location has already delivered a fix with
  /// `sourceInformation.isSimulatedBySoftware` set (iOS 15+), that's a strong
  /// signal. Without location permission or a fix there is nothing to inspect,
  /// which is reported as a low-confidence "not detected" — this SDK never
  /// requests location permission just to run a check.
  func checkMockLocation() -> NativeDetectionResult {
    #if canImport(CoreLocation) && os(iOS)
    let manager = onMainThread { CLLocationManager() }
    let status = manager.authorizationStatus
    guard status == .authorizedWhenInUse || status == .authorizedAlways else {
      return lowConfidenceClean("location permission not granted; nothing to inspect")
    }
    guard let location = manager.location else {
      return lowConfidenceClean("no cached location fix to inspect")
    }
    let simulated = location.sourceInformation?.isSimulatedBySoftware ?? false
    return Detection.run { d in
      d.signal("SIMULATED_LOCATION", .high) { simulated }
    }
    #else
    return Detection.unsupported()
    #endif
  }

  private func lowConfidenceClean(_ note: String) -> NativeDetectionResult {
    NativeDetectionResult(status: .notDetected, reasons: [], confidence: .low, error: note)
  }

  /// `CLLocationManager` must be created on a thread with a run loop.
  private func onMainThread<T>(_ work: () -> T) -> T {
    Thread.isMainThread ? work() : DispatchQueue.main.sync(execute: work)
  }
}
