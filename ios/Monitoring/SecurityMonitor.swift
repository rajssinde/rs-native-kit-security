import Foundation
#if canImport(UIKit)
import UIKit
#endif

struct SecurityMonitorEvent {
  let type: String
  let message: String
  let timestamp: Double
}

/**
 * Drives the JS event system. Screenshot and screen-recording changes use
 * real OS push notifications (`userDidTakeScreenshotNotification`,
 * `UIScreen.capturedDidChangeNotification`); everything without a
 * first-class iOS push API (jailbreak/hook/debugger/tamper/VPN/proxy state)
 * is re-evaluated on a short poll, only emitting on a false→true transition
 * so a stable device doesn't spam listeners.
 */
final class SecurityMonitor {
  private static let pollInterval: TimeInterval = 4.0

  private let jailbreakDetector: JailbreakDetector
  private let hookDetector: HookDetector
  private let integrityChecker: IntegrityChecker
  private let networkMonitor: NetworkMonitor
  private let screenMonitor: ScreenMonitor
  private let developerModeDetector: DeveloperModeDetector
  private let onEvent: (SecurityMonitorEvent) -> Void

  private let lock = NSLock()
  private var isRunning = false
  private var pollTimer: DispatchSourceTimer?
  private var notificationObservers: [NSObjectProtocol] = []

  private var wasVpnConnected = false
  private var wasProxyEnabled = false
  private var wasJailbroken = false
  private var wasHookDetected = false
  private var wasDebuggerAttached = false
  private var wasTampered = false
  private var wasScreenRecording = false

  init(
    jailbreakDetector: JailbreakDetector,
    hookDetector: HookDetector,
    integrityChecker: IntegrityChecker,
    networkMonitor: NetworkMonitor,
    screenMonitor: ScreenMonitor,
    developerModeDetector: DeveloperModeDetector,
    onEvent: @escaping (SecurityMonitorEvent) -> Void
  ) {
    self.jailbreakDetector = jailbreakDetector
    self.hookDetector = hookDetector
    self.integrityChecker = integrityChecker
    self.networkMonitor = networkMonitor
    self.screenMonitor = screenMonitor
    self.developerModeDetector = developerModeDetector
    self.onEvent = onEvent
  }

  func start() {
    lock.lock()
    defer { lock.unlock() }
    guard !isRunning else { return }
    isRunning = true

    registerNotifications()
    startPolling()
  }

  func stop() {
    lock.lock()
    defer { lock.unlock() }
    guard isRunning else { return }
    isRunning = false

    unregisterNotifications()
    pollTimer?.cancel()
    pollTimer = nil
  }

  private func emit(_ type: String, _ message: String) {
    onEvent(SecurityMonitorEvent(type: type, message: message, timestamp: Date().timeIntervalSince1970 * 1000))
  }

  // MARK: - Real push notifications

  private func registerNotifications() {
    #if canImport(UIKit) && !os(watchOS)
    let center = NotificationCenter.default

    let screenshotObserver = center.addObserver(
      forName: UIApplication.userDidTakeScreenshotNotification,
      object: nil,
      queue: .main
    ) { [weak self] _ in
      self?.screenMonitor.markScreenshotDetected()
      self?.emit("SCREENSHOT", "A screenshot was captured")
    }

    let captureObserver = center.addObserver(
      forName: UIScreen.capturedDidChangeNotification,
      object: nil,
      queue: .main
    ) { [weak self] _ in
      guard let self else { return }
      let recording = self.screenMonitor.isScreenRecording()
      if recording && !self.wasScreenRecording {
        self.emit("SCREEN_RECORDING", "Screen recording/mirroring started")
      }
      self.wasScreenRecording = recording
    }

    notificationObservers = [screenshotObserver, captureObserver]
    #endif
  }

  private func unregisterNotifications() {
    #if canImport(UIKit) && !os(watchOS)
    let center = NotificationCenter.default
    notificationObservers.forEach { center.removeObserver($0) }
    #endif
    notificationObservers = []
  }

  // MARK: - Polling

  private func startPolling() {
    let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
    timer.schedule(deadline: .now() + Self.pollInterval, repeating: Self.pollInterval)
    timer.setEventHandler { [weak self] in self?.pollOnce() }
    timer.resume()
    pollTimer = timer
  }

  private func pollOnce() {
    let jailbroken = jailbreakDetector.isJailbroken()
    if jailbroken && !wasJailbroken {
      emit("JAILBREAK_DETECTED", "Jailbreak detected on this device")
    }
    wasJailbroken = jailbroken

    let hooked = hookDetector.isAnyHookDetected()
    if hooked && !wasHookDetected {
      emit("HOOK_DETECTED", "An instrumentation/hooking framework was detected")
    }
    wasHookDetected = hooked

    let debugger = developerModeDetector.isDebuggerAttached()
    if debugger && !wasDebuggerAttached {
      emit("DEBUGGER", "A debugger attached to the app process")
    }
    wasDebuggerAttached = debugger

    let tampered = integrityChecker.isTampered()
    if tampered && !wasTampered {
      emit("TAMPER", "App tamper signal detected")
    }
    wasTampered = tampered

    let vpn = networkMonitor.isVpnConnected()
    if vpn && !wasVpnConnected {
      emit("VPN_CONNECTED", "VPN connection detected")
    }
    wasVpnConnected = vpn

    let proxy = networkMonitor.isProxyEnabled()
    if proxy && !wasProxyEnabled {
      emit("PROXY_ENABLED", "System proxy configuration detected")
    }
    wasProxyEnabled = proxy
  }
}
