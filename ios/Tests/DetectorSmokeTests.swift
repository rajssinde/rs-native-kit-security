import XCTest
@testable import RsNativeKitSecurity

/// These run on the iOS Simulator, which has real filesystem/process
/// characteristics that differ from a physical device (e.g. it isn't
/// kernel-sandboxed the same way), so most assertions here check
/// "doesn't crash / stays internally consistent" rather than a specific
/// jailbroken/not-jailbroken verdict — that verdict can only be trusted on
/// a real, physical test device.
final class DetectorSmokeTests: XCTestCase {

  private let validStatuses: [NativeDetectionStatus] = [.detected, .notDetected, .unsupported, .notConfigured, .error]

  private func assertWellFormed(_ result: NativeDetectionResult, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertTrue(validStatuses.contains(result.status), file: file, line: line)
    if result.status == .detected {
      XCTAssertFalse(result.reasons.isEmpty, "a detection must say why", file: file, line: line)
    }
    if result.status == .error {
      XCTAssertNotNil(result.error, "an error must carry its cause", file: file, line: line)
    }
  }

  func testEmulatorDetectorReportsSimulatorWhenRunningInTheSimulator() {
    let result = EmulatorDetector().check()
    XCTAssertEqual(result.status, .detected)
    XCTAssertEqual(result.reasons, ["SIMULATOR"])
  }

  func testJailbreakDetectionIsUnsupportedInTheSimulator() {
    // The Simulator shares the Mac's filesystem, so jailbreak signals are meaningless there.
    let detector = JailbreakDetector()
    XCTAssertEqual(detector.check().status, .unsupported)
    XCTAssertFalse(detector.isJailbroken())
  }

  func testHookUmbrellaIncludesFridaReasons() {
    let detector = HookDetector()
    let frida = detector.checkFrida()
    let hooks = detector.checkHooks(frida: frida)
    assertWellFormed(hooks)
    for reason in frida.reasons {
      XCTAssertTrue(hooks.reasons.contains(reason))
    }
  }

  func testNetworkChecksAreWellFormed() {
    let monitor = NetworkMonitor()
    assertWellFormed(monitor.checkVpn())
    assertWellFormed(monitor.checkProxy())
  }

  func testScreenCaptureIsLowConfidenceUntilScreenshotsAreObserved() {
    let monitor = ScreenMonitor()
    XCTAssertEqual(monitor.checkScreenCapture().confidence, .low)

    monitor.isObservingScreenshots = true
    XCTAssertEqual(monitor.checkScreenCapture().confidence, .medium)

    monitor.markScreenshotDetected()
    XCTAssertEqual(monitor.checkScreenCapture().status, .detected)
  }

  func testDebuggerCheckIsWellFormed() {
    // XCTest may or may not run traced depending on the environment.
    assertWellFormed(DeveloperModeDetector().checkDebugger())
  }

  func testSignatureCheckWithoutExpectedSignersIsNotConfigured() {
    let result = IntegrityChecker().checkSignature(expectedSigners: [])
    XCTAssertEqual(result.status, .notConfigured)
    XCTAssertEqual(result.reasons, ["SIGNATURE_HASH_NOT_CONFIGURED"])
  }

  func testSignatureCheckRejectsMalformedTeamIds() {
    XCTAssertEqual(IntegrityChecker().checkSignature(expectedSigners: ["your-team-id"]).status, .error)
  }
}
