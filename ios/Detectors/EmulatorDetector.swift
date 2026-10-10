import Foundation

/// iOS Simulator detection. `targetEnvironment(simulator)` is a compile-time
/// flag resolved per architecture slice, so this is accurate (unlike the
/// Android emulator heuristics, which are runtime signal-based).
final class EmulatorDetector {
  func check() -> NativeDetectionResult {
    Detection.run { d in
      d.signal("SIMULATOR", .high) { isDetected() }
    }
  }

  func isDetected() -> Bool {
    #if targetEnvironment(simulator)
    return true
    #else
    return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    #endif
  }
}
