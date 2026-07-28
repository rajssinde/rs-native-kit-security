import XCTest
@testable import RsNativeKitSecurity

final class DylibScannerTests: XCTestCase {
  func testLoadedImageNamesIsNonEmpty() {
    // Every iOS process has at least the executable itself and Foundation loaded.
    XCTAssertFalse(DylibScanner.loadedImageNames().isEmpty)
  }

  func testAnyLoadedImageContainsFindsARealLoadedFramework() {
    XCTAssertTrue(DylibScanner.anyLoadedImageContains(["Foundation"]))
  }

  func testAnyLoadedImageContainsIsFalseForNonsenseMarker() {
    XCTAssertFalse(DylibScanner.anyLoadedImageContains(["definitely-not-a-real-loaded-library-12345"]))
  }
}
