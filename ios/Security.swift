import Foundation
import NitroModules

/**
 * Composition root: implements the Nitro `Security` spec by delegating to
 * the individual detectors under `Detectors/`, and the event system to
 * `Monitoring/SecurityMonitor`. Every method runs via `Promise.parallel` —
 * detection work never touches the JS thread.
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

  // MARK: - Root (Android-only concept)

  func isRooted() throws -> Promise<Bool> { Promise.resolved(withResult: false) }
  func isMagiskDetected() throws -> Promise<Bool> { Promise.resolved(withResult: false) }
  func isBusyBoxDetected() throws -> Promise<Bool> { Promise.resolved(withResult: false) }

  // MARK: - Jailbreak

  func isJailbroken() throws -> Promise<Bool> {
    Promise.parallel { [jailbreakDetector] in jailbreakDetector.isJailbroken() }
  }

  // MARK: - Simulator

  func isEmulator() throws -> Promise<Bool> {
    Promise.parallel { [emulatorDetector] in emulatorDetector.isDetected() }
  }

  // MARK: - Developer/debug state

  func isDeveloperModeEnabled() throws -> Promise<Bool> {
    Promise.parallel { [developerModeDetector] in developerModeDetector.isDeveloperModeEnabled() }
  }

  func isUsbDebuggingEnabled() throws -> Promise<Bool> {
    Promise.resolved(withResult: false)
  }

  func isDebuggerAttached() throws -> Promise<Bool> {
    Promise.parallel { [developerModeDetector] in developerModeDetector.isDebuggerAttached() }
  }

  func isMockLocationEnabled() throws -> Promise<Bool> {
    Promise.parallel { [developerModeDetector] in developerModeDetector.isMockLocationEnabled() }
  }

  // MARK: - Network

  func isVpnConnected() throws -> Promise<Bool> {
    Promise.parallel { [networkMonitor] in networkMonitor.isVpnConnected() }
  }

  func isProxyEnabled() throws -> Promise<Bool> {
    Promise.parallel { [networkMonitor] in networkMonitor.isProxyEnabled() }
  }

  // MARK: - Screen

  func isScreenRecording() throws -> Promise<Bool> {
    Promise.parallel { [screenMonitor] in screenMonitor.isScreenRecording() }
  }

  func isScreenCaptured() throws -> Promise<Bool> {
    Promise.parallel { [screenMonitor] in screenMonitor.isScreenCaptured() }
  }

  // MARK: - Overlay (Android-only concept)

  func hasOverlayPermission() throws -> Promise<Bool> {
    Promise.resolved(withResult: false)
  }

  // MARK: - Hooking frameworks

  func isHookDetected() throws -> Promise<Bool> {
    Promise.parallel { [hookDetector] in hookDetector.isAnyHookDetected() }
  }

  func isFridaDetected() throws -> Promise<Bool> {
    Promise.parallel { [hookDetector] in hookDetector.isFridaDetected() }
  }

  /// Xposed/LSPosed are Android-only frameworks; always `false` on iOS.
  func isXposedDetected() throws -> Promise<Bool> { Promise.resolved(withResult: false) }
  func isLSPosedDetected() throws -> Promise<Bool> { Promise.resolved(withResult: false) }

  // MARK: - Integrity / tamper / signature

  func isTampered() throws -> Promise<Bool> {
    Promise.parallel { [integrityChecker] in integrityChecker.isTampered() }
  }

  func getAppSignatureHash() throws -> Promise<String> {
    Promise.parallel { [integrityChecker] in try integrityChecker.getAppSignatureHash() }
  }

  func verifyAppSignature(expectedSignatureHash: String) throws -> Promise<Bool> {
    Promise.parallel { [integrityChecker] in
      integrityChecker.verifyAppSignature(expectedSignatureHash: expectedSignatureHash)
    }
  }

  /// APKs are an Android concept; always "valid" (not applicable) on iOS.
  func verifyApkIntegrity(expectedSha256: String) throws -> Promise<Bool> {
    Promise.resolved(withResult: true)
  }

  /// iOS's `URLSession`/`NSURLSession` always supports pinning; this is informational.
  func isSslPinningSupported() throws -> Promise<Bool> {
    Promise.resolved(withResult: true)
  }

  // MARK: - Aggregate scan

  func scan() throws -> Promise<NativeScanResult> {
    Promise.parallel { [self] in
      var reasons: [String] = []

      let jailbreakReasons = jailbreakDetector.reasons()
      reasons += jailbreakReasons
      let isJailbrokenValue = !jailbreakReasons.isEmpty

      let isEmu = emulatorDetector.isDetected()
      if isEmu { reasons.append("Running on the iOS Simulator") }

      let isFrida = hookDetector.isFridaDetected()
      if isFrida { reasons.append("Frida detected") }
      let hookAny = isFrida

      let devMode = developerModeDetector.isDeveloperModeEnabled()
      if devMode { reasons.append("Development-signed build (embedded provisioning profile present)") }

      let debuggerAttached = developerModeDetector.isDebuggerAttached()
      if debuggerAttached { reasons.append("Debugger attached to process") }

      let mockLoc = developerModeDetector.isMockLocationEnabled()
      if mockLoc { reasons.append("Simulated location provider detected") }

      let vpn = networkMonitor.isVpnConnected()
      if vpn { reasons.append("VPN connection active") }

      let proxy = networkMonitor.isProxyEnabled()
      if proxy { reasons.append("System proxy configured") }

      let screenRec = screenMonitor.isScreenRecording()
      if screenRec { reasons.append("Screen is being recorded/mirrored") }

      let screenCap = screenMonitor.isScreenCaptured()

      let tampered = integrityChecker.isTampered()
      if tampered { reasons.append("App tamper signal detected (non-distribution provisioning entitlement)") }
      // No app-supplied "known good" hash is available in a zero-config scan();
      // call verifyAppSignature() directly for an authoritative check.
      let signatureValid = true

      let checks = NativeSecurityChecks(
        root: false,
        jailbreak: isJailbrokenValue,
        emulator: isEmu,
        developerMode: devMode,
        usbDebugging: false,
        vpn: vpn,
        proxy: proxy,
        overlay: false,
        frida: isFrida,
        xposed: false,
        lsposed: false,
        magisk: false,
        busybox: false,
        mockLocation: mockLoc,
        hookDetected: hookAny,
        tampered: tampered,
        signatureValid: signatureValid,
        sslPinningSupported: true,
        screenRecording: screenRec,
        screenCaptured: screenCap,
        debuggerAttached: debuggerAttached
      )

      return NativeScanResult(checks: checks, reasons: reasons)
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
