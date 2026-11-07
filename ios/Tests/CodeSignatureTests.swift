import XCTest
@testable import RsNativeKitSecurity

/// Builds minimal synthetic Mach-O binaries so the parser is tested
/// independently of how the simulator happens to sign the test host.
final class CodeSignatureTests: XCTestCase {

  private func be32(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.bigEndian, Array.init) }
  private func le32(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.littleEndian, Array.init) }

  /// Thin 64-bit Mach-O: header, one LC_CODE_SIGNATURE, then a superblob holding an entitlements blob.
  private func machO(entitlements: String) -> Data {
    let plist = Array(entitlements.utf8)
    let entitlementsBlob = be32(0xfade_7171) + be32(UInt32(8 + plist.count)) + plist
    let superBlob = be32(0xfade_0cc0) + be32(UInt32(20 + entitlementsBlob.count)) + be32(1)
      + be32(5) + be32(20) // index entry: slot 5 (entitlements) at offset 20
      + entitlementsBlob

    let headerSize = 32
    let commandSize = 16
    let signatureOffset = UInt32(headerSize + commandSize)
    var bytes = le32(0xfeed_facf) + le32(0x0100_000c) + le32(0) + le32(2) // magic, cputype, subtype, filetype
    bytes += le32(1) + le32(UInt32(commandSize)) + le32(0) + le32(0) // ncmds, sizeofcmds, flags, reserved
    bytes += le32(0x1d) + le32(UInt32(commandSize)) + le32(signatureOffset) + le32(UInt32(superBlob.count))
    bytes += superBlob
    return Data(bytes)
  }

  private func plist(_ body: String) -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>\(body)</dict></plist>
    """
  }

  func testExtractsTeamIdFromApplicationIdentifier() throws {
    let binary = machO(entitlements: plist("<key>application-identifier</key><string>AB12CD34EF.com.example.app</string>"))
    let entitlements = try CodeSignature.entitlementsPlist(fromMachO: binary)
    XCTAssertEqual(try CodeSignature.teamIdentifier(fromEntitlements: entitlements), "AB12CD34EF")
  }

  func testPrefersExplicitTeamIdentifierEntitlement() throws {
    let binary = machO(entitlements: plist("""
      <key>com.apple.developer.team-identifier</key><string>ZZ99YY88XX</string>
      <key>application-identifier</key><string>AB12CD34EF.com.example.app</string>
      """))
    let entitlements = try CodeSignature.entitlementsPlist(fromMachO: binary)
    XCTAssertEqual(try CodeSignature.teamIdentifier(fromEntitlements: entitlements), "ZZ99YY88XX")
  }

  func testRejectsBundleIdWithoutTeamPrefix() throws {
    let binary = machO(entitlements: plist("<key>application-identifier</key><string>com.apple.Safari</string>"))
    let entitlements = try CodeSignature.entitlementsPlist(fromMachO: binary)
    XCTAssertThrowsError(try CodeSignature.teamIdentifier(fromEntitlements: entitlements))
  }

  func testTruncatedBinaryThrowsInsteadOfCrashing() {
    let binary = machO(entitlements: plist(""))
    XCTAssertThrowsError(try CodeSignature.entitlementsPlist(fromMachO: binary.prefix(40)))
    XCTAssertThrowsError(try CodeSignature.entitlementsPlist(fromMachO: Data([0xcf, 0xfa])))
  }

  func testTeamIdentifierFormat() {
    XCTAssertTrue(CodeSignature.isTeamIdentifier("AB12CD34EF"))
    XCTAssertFalse(CodeSignature.isTeamIdentifier("ab12cd34ef"))
    XCTAssertFalse(CodeSignature.isTeamIdentifier("AB12CD34E"))
    XCTAssertFalse(CodeSignature.isTeamIdentifier("com"))
  }
}
