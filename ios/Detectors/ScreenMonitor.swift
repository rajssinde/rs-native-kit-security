import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Unlike Android, iOS exposes a direct, accurate API for screen recording
/// (`UIScreen.isCaptured` covers AirPlay mirroring, QuickTime recording,
/// and in-app screen recording alike). Screenshot detection uses the
/// real `userDidTakeScreenshotNotification` push notification, wired up by
/// `SecurityMonitor`, which calls `markScreenshotDetected` — so it can only
/// observe anything while monitoring is running.
final class ScreenMonitor {

  private static let recentScreenshotWindow: TimeInterval = 5.0

  private let lock = NSLock()
  private var lastScreenshotAt: Date?
  private var observingScreenshots = false

  var isObservingScreenshots: Bool {
    get { lock.lock(); defer { lock.unlock() }; return observingScreenshots }
    set { lock.lock(); observingScreenshots = newValue; lock.unlock() }
  }

  func isScreenRecording() -> Bool {
    #if canImport(UIKit) && !os(watchOS)
    if Thread.isMainThread {
      return UIScreen.main.isCaptured
    }
    var result = false
    DispatchQueue.main.sync { result = UIScreen.main.isCaptured }
    return result
    #else
    return false
    #endif
  }

  func checkScreenRecording() -> NativeDetectionResult {
    Detection.run { d in
      d.signal("SCREEN_CAPTURED", .high) { isScreenRecording() }
    }
  }

  func checkScreenCapture() -> NativeDetectionResult {
    lock.lock()
    let last = lastScreenshotAt
    let observing = observingScreenshots
    lock.unlock()

    if let last, Date().timeIntervalSince(last) < Self.recentScreenshotWindow {
      return NativeDetectionResult(status: .detected, reasons: ["SCREENSHOT_RECENT"], confidence: .medium, error: nil)
    }
    return NativeDetectionResult(
      status: .notDetected,
      reasons: [],
      confidence: observing ? .medium : .low,
      error: observing ? nil : "screenshot monitoring is not running; call addListener() to observe screenshots"
    )
  }

  func markScreenshotDetected() {
    lock.lock()
    lastScreenshotAt = Date()
    lock.unlock()
  }
}
