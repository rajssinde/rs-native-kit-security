import Foundation

/**
 * iOS has no Android-`PackageManager`-style API for reading your own signing
 * certificate, and App Store binaries are re-signed with Apple's certificate
 * anyway, so a certificate hash would be identical for every App Store app.
 * This checker does what a userland iOS process legitimately can:
 *
 * - `checkSignature()` compares the **Team ID** from the app's own
 *   code-signature entitlements (see `CodeSignature`) against the Team IDs
 *   you configure. Re-signing an IPA under another developer account changes
 *   it. An attacker who patches this check out defeats it — pair it with App
 *   Attest for a guarantee the device can't fake.
 * - `checkTampering()` (release builds only) flags the `get-task-allow`
 *   development entitlement in the embedded provisioning profile: a release
 *   build carrying it was re-signed with a development profile, the usual way
 *   a modified IPA gets sideloaded.
 */
final class IntegrityChecker {

  /// Debug builds are development-signed with `get-task-allow` by design, so
  /// the signal only means something in release builds (CocoaPods compiles
  /// this pod with `DEBUG` in debug-type configurations).
  func checkTampering() -> NativeDetectionResult {
    #if DEBUG
    return NativeDetectionResult(status: .unsupported, reasons: ["DEBUG_BUILD"], confidence: .high, error: nil)
    #else
    return Detection.run { d in
      d.signal("DEVELOPMENT_SIGNED_RELEASE", .high) { try hasDebugEntitlement() }
    }
    #endif
  }

  func isTampered() -> Bool {
    checkTampering().isDetected
  }

  /// Team ID of whoever signed the running app.
  func getSigningIdentity() throws -> String {
    try CodeSignature.teamIdentifier()
  }

  /// `detected` = the app's Team ID matches none of `expectedSigners`.
  func checkSignature(expectedSigners: [String]) -> NativeDetectionResult {
    let provided = expectedSigners.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    if provided.isEmpty {
      return Detection.notConfigured("SIGNATURE_HASH_NOT_CONFIGURED")
    }
    // A malformed configured value is a config bug: report it, don't treat it as "not configured".
    if let invalid = provided.first(where: { !CodeSignature.isTeamIdentifier($0) }) {
      return Detection.failed(DetectionError("\"\(invalid)\" is not an Apple Team ID (expected 10 uppercase letters/digits)"))
    }
    return Detection.run { d in
      d.signal("SIGNATURE_MISMATCH", .high) {
        !provided.contains(try CodeSignature.teamIdentifier())
      }
    }
  }

  /// `true` if the embedded provisioning profile grants `get-task-allow`.
  /// App Store builds ship no profile, so they never trip this.
  private func hasDebugEntitlement() throws -> Bool {
    guard let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
      return false
    }
    guard let data = FileManager.default.contents(atPath: provisioningPath) else {
      throw DetectionError("embedded.mobileprovision is unreadable")
    }
    guard let plistData = extractPlist(from: data),
          let profile = try PropertyListSerialization.propertyList(from: plistData, options: PropertyListSerialization.ReadOptions(), format: nil) as? [String: Any]
    else {
      throw DetectionError("embedded.mobileprovision has no readable plist payload")
    }
    let entitlements = profile["Entitlements"] as? [String: Any]
    return (entitlements?["get-task-allow"] as? Bool) == true
  }

  /// `embedded.mobileprovision` is a CMS/PKCS#7-signed file, but the
  /// embedded plist payload itself is plaintext — extracting the
  /// `<?xml ... </plist>` substring directly avoids needing a full CMS
  /// parser just to read entitlements.
  private func extractPlist(from data: Data) -> Data? {
    guard let start = data.range(of: Data("<?xml".utf8)),
          let end = data.range(of: Data("</plist>".utf8), in: start.upperBound..<data.endIndex)
    else {
      return nil
    }
    return data.subdata(in: start.lowerBound..<end.upperBound)
  }
}
