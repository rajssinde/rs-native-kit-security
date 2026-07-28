import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Unlike Android, iOS exposes a direct, accurate API for screen recording
/// (`UIScreen.isCaptured` covers AirPlay mirroring, QuickTime recording,
/// and in-app screen recording alike). Screenshot detection uses the
/// real `userDidTakeScreenshotNotification` push notification, wired up by
/// `SecurityMonitor`, which calls [markScreenshotDetected].
final class ScreenMonitor {

  private static let recentScreenshotWindow: TimeInterval = 5.0

  private let lock = NSLock()
  private var lastScreenshotAt: Date?

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

  func isScreenCaptured() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard let lastScreenshotAt else { return false }
    return Date().timeIntervalSince(lastScreenshotAt) < Self.recentScreenshotWindow
  }

  func markScreenshotDetected() {
    lock.lock()
    lastScreenshotAt = Date()
    lock.unlock()
  }
}
