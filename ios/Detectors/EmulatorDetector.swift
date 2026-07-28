import Foundation

/// iOS Simulator detection. `targetEnvironment(simulator)` is a compile-time
/// flag resolved per architecture slice, so this is 100% accurate (unlike
/// the Android emulator heuristics, which are runtime signal-based).
final class EmulatorDetector {
  func isDetected() -> Bool {
    #if targetEnvironment(simulator)
    return true
    #else
    return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    #endif
  }
}
