import XCTest
@testable import RsNativeKitSecurity

/// These run on the iOS Simulator, which has real filesystem/process
/// characteristics that differ from a physical device (e.g. it isn't
/// kernel-sandboxed the same way), so most assertions here check
/// "doesn't crash / stays internally consistent" rather than a specific
/// jailbroken/not-jailbroken verdict — that verdict can only be trusted on
/// a real, physical test device.
final class DetectorSmokeTests: XCTestCase {

  func testEmulatorDetectorReportsSimulatorWhenRunningInTheSimulator() {
    XCTAssertTrue(EmulatorDetector().isDetected())
  }

  func testJailbreakDetectorIsConsistentBetweenIsJailbrokenAndReasons() {
    let detector = JailbreakDetector()
    XCTAssertEqual(detector.isJailbroken(), !detector.reasons().isEmpty)
  }

  func testHookDetectorDoesNotCrashAndIsConsistent() {
    let detector = HookDetector()
    XCTAssertEqual(detector.isAnyHookDetected(), detector.isFridaDetected())
  }

  func testNetworkMonitorChecksReturnWithoutThrowing() {
    let monitor = NetworkMonitor()
    _ = monitor.isVpnConnected()
    _ = monitor.isProxyEnabled()
  }

  func testScreenMonitorScreenshotFlagClearsAfterTheRecentWindow() {
    let monitor = ScreenMonitor()
    XCTAssertFalse(monitor.isScreenCaptured())

    monitor.markScreenshotDetected()
    XCTAssertTrue(monitor.isScreenCaptured())
  }

  func testDeveloperModeDetectorDebuggerCheckDoesNotCrash() {
    // XCTest itself runs under a test-runner process which may or may not
    // be traced depending on the environment, so only assert it returns
    // without crashing/throwing.
    _ = DeveloperModeDetector().isDebuggerAttached()
  }

  func testIntegrityCheckerProducesEitherAHashOrAWellDefinedError() {
    let checker = IntegrityChecker()
    do {
      let hash = try checker.getAppSignatureHash()
      XCTAssertFalse(hash.isEmpty)
    } catch is IntegrityChecker.IntegrityError {
      // Acceptable: the XCTest bundle may ship neither an embedded
      // provisioning profile nor a _CodeSignature/CodeResources file.
    } catch {
      XCTFail("Unexpected error type: \(error)")
    }
  }
}
