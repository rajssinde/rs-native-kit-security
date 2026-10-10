import Foundation
import NitroModules

/**
 * Composition root: implements the Nitro `Security` spec by delegating to
 * the individual detectors under `Detectors/`, and the event system to
 * `Monitoring/SecurityMonitor`. Every method runs via `Promise.parallel` —
 * detection work never touches the JS thread. Detectors never throw: a check
 * that can't run reports an `error` result instead.
 */
class Security: HybridSecuritySpec {

  private let jailbreakDetector = JailbreakDetector()
  private let emulatorDetector = EmulatorDetector()
  private let hookDetector = HookDetector()
  private let developerModeDetector = DeveloperModeDetector()
  private let networkMonitor = NetworkMonitor()
  private let screenMonitor = ScreenMonitor()
  private let integrityChecker = IntegrityChecker()

  private let listenerLock = NSLock()
  private var eventListener: ((NativeSecurityEvent) -> Void)?

  private lazy var monitor = SecurityMonitor(
    jailbreakDetector: jailbreakDetector,
    hookDetector: hookDetector,
    integrityChecker: integrityChecker,
    networkMonitor: networkMonitor,
    screenMonitor: screenMonitor,
    developerModeDetector: developerModeDetector
  ) { [weak self] event in
    self?.listenerLock.lock()
    let listener = self?.eventListener
    self?.listenerLock.unlock()
    listener?(NativeSecurityEvent(type: event.type, message: event.message, timestamp: event.timestamp))
  }

  private func async(_ check: @escaping () -> NativeDetectionResult) -> Promise<NativeDetectionResult> {
    Promise.parallel { check() }
  }

  private func unsupported() -> Promise<NativeDetectionResult> {
    Promise.resolved(withResult: Detection.unsupported())
  }

  // MARK: - Root (Android-only concept)

  func checkRoot() throws -> Promise<NativeDetectionResult> { unsupported() }
  func checkMagisk() throws -> Promise<NativeDetectionResult> { unsupported() }
  func checkBusyBox() throws -> Promise<NativeDetectionResult> { unsupported() }

  // MARK: - Jailbreak / Simulator

  func checkJailbreak() throws -> Promise<NativeDetectionResult> { async(jailbreakDetector.check) }
  func checkEmulator() throws -> Promise<NativeDetectionResult> { async(emulatorDetector.check) }

  // MARK: - Developer/debug state

  func checkDeveloperMode() throws -> Promise<NativeDetectionResult> { async(developerModeDetector.checkDeveloperMode) }

  /// USB debugging (ADB) has no iOS equivalent — Xcode uses a paired trust relationship, not a toggle.
  func checkUsbDebugging() throws -> Promise<NativeDetectionResult> { unsupported() }

  func checkDebugger() throws -> Promise<NativeDetectionResult> { async(developerModeDetector.checkDebugger) }
  func checkMockLocation() throws -> Promise<NativeDetectionResult> { async(developerModeDetector.checkMockLocation) }

  // MARK: - Network

  func checkVpn() throws -> Promise<NativeDetectionResult> { async(networkMonitor.checkVpn) }
  func checkProxy() throws -> Promise<NativeDetectionResult> { async(networkMonitor.checkProxy) }

  // MARK: - Screen

  func checkScreenRecording() throws -> Promise<NativeDetectionResult> { async(screenMonitor.checkScreenRecording) }
  func checkScreenCapture() throws -> Promise<NativeDetectionResult> { async(screenMonitor.checkScreenCapture) }

  // MARK: - Overlay (Android-only concept)

  func checkOverlay() throws -> Promise<NativeDetectionResult> { unsupported() }

  // MARK: - Hooking frameworks

  func checkHooks() throws -> Promise<NativeDetectionResult> { async { self.hookDetector.checkHooks() } }
  func checkFrida() throws -> Promise<NativeDetectionResult> { async(hookDetector.checkFrida) }

  /// Xposed/LSPosed are Android-only frameworks.
  func checkXposed() throws -> Promise<NativeDetectionResult> { unsupported() }
  func checkLSPosed() throws -> Promise<NativeDetectionResult> { unsupported() }

  // MARK: - Integrity / tamper / signature

  func checkTampering() throws -> Promise<NativeDetectionResult> { async(integrityChecker.checkTampering) }

  func checkSignature(expectedSigners: [String]) throws -> Promise<NativeDetectionResult> {
    async { self.integrityChecker.checkSignature(expectedSigners: expectedSigners) }
  }

  /// APKs are an Android concept.
  func checkApkIntegrity(expectedSha256: String) throws -> Promise<NativeDetectionResult> { unsupported() }

  func getSigningIdentity() throws -> Promise<String> {
    Promise.parallel { [integrityChecker] in try integrityChecker.getSigningIdentity() }
  }

  // MARK: - Aggregate scan

  func scan(options: NativeScanOptions) throws -> Promise<NativeScanResult> {
    Promise.parallel { [self] in
      let startedAt = Date()
      let unsupported = Detection.unsupported()
      let frida = hookDetector.checkFrida()

      let checks = NativeSecurityChecks(
        root: unsupported,
        magisk: unsupported,
        busybox: unsupported,
        jailbreak: jailbreakDetector.check(),
        emulator: emulatorDetector.check(),
        developerMode: developerModeDetector.checkDeveloperMode(),
        usbDebugging: unsupported,
        debugger: developerModeDetector.checkDebugger(),
        mockLocation: developerModeDetector.checkMockLocation(),
        vpn: networkMonitor.checkVpn(),
        proxy: networkMonitor.checkProxy(),
        screenRecording: screenMonitor.checkScreenRecording(),
        screenCapture: screenMonitor.checkScreenCapture(),
        overlay: unsupported,
        // Reuse the Frida result instead of running its probes twice.
        hooks: hookDetector.checkHooks(frida: frida),
        frida: frida,
        xposed: unsupported,
        lsposed: unsupported,
        tampering: integrityChecker.checkTampering(),
        signature: integrityChecker.checkSignature(expectedSigners: options.expectedSigners)
      )

      return NativeScanResult(checks: checks, durationMs: Date().timeIntervalSince(startedAt) * 1000)
    }
  }

  // MARK: - Event system

  func setEventListener(listener: @escaping (_ event: NativeSecurityEvent) -> Void) throws {
    listenerLock.lock()
    eventListener = listener
    listenerLock.unlock()
  }

  func removeEventListener() throws {
    listenerLock.lock()
    eventListener = nil
    listenerLock.unlock()
  }

  func startMonitoring() throws {
    monitor.start()
  }

  func stopMonitoring() throws {
    monitor.stop()
  }
}
