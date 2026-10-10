import Foundation
import CryptoKit

/**
 * iOS deliberately does not expose an Android-`PackageManager`-style API for
 * reading your own signing certificate at runtime, and unlike macOS, the
 * iOS SDK does not expose the Code Signing Services APIs
 * (`SecStaticCodeCheckValidity` & friends) at all — code-signature
 * enforcement happens at the OS/kernel level before your code ever runs,
 * with no public in-process way to re-verify it. This checker does the
 * best a userland iOS process legitimately can:
 *
 * - `isTampered()` uses the `get-task-allow` entitlement embedded in the
 *   provisioning profile as a "this is not an App Store distribution
 *   build" signal — the same category of weak-but-real heuristic as
 *   Android's `FLAG_DEBUGGABLE` check. It cannot detect a full, consistent
 *   re-sign under an attacker's own certificate — nothing running inside
 *   the app process legitimately can. Pair this with server-side
 *   attestation (App Attest/DeviceCheck) for a strong guarantee — see the
 *   Security Notes doc.
 * - `getAppSignatureHash()`/`verifyAppSignature()` hash the embedded
 *   provisioning profile (present on Development/Ad Hoc/Enterprise builds)
 *   as a practical "did this exact build's signing identity change"
 *   fingerprint. App Store builds don't ship a provisioning profile, so
 *   this falls back to hashing the bundle's `CodeResources` manifest.
 */
final class IntegrityChecker {

  /// Debug builds are development-signed with `get-task-allow` by design, so
  /// the signal only means something in release builds (CocoaPods compiles
  /// this pod with `DEBUG` in debug-type configurations). A release build
  /// carrying `get-task-allow` was re-signed with a development profile — the
  /// usual way a modified IPA gets sideloaded.
  func isTampered() -> Bool {
    #if DEBUG
    return false
    #else
    return hasDebugEntitlement()
    #endif
  }

  func getAppSignatureHash() throws -> String {
    if let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
       let data = FileManager.default.contents(atPath: provisioningPath) {
      return sha256Hex(data)
    }

    // App Store builds ship no embedded.mobileprovision; fall back to the
    // signature manifest every signed bundle does have.
    if let resourcesUrl = Bundle.main.url(forResource: "CodeResources", withExtension: nil, subdirectory: "_CodeSignature"),
       let data = try? Data(contentsOf: resourcesUrl) {
      return sha256Hex(data)
    }

    throw IntegrityError.signatureUnavailable
  }

  func verifyAppSignature(expectedSignatureHash: String) -> Bool {
    guard let actual = try? getAppSignatureHash() else { return false }
    return actual.caseInsensitiveCompare(expectedSignatureHash) == .orderedSame
  }

  /// APKs are an Android concept; always "valid" (not applicable) on iOS.
  func verifyApkIntegrity(expectedSha256: String) -> Bool {
    return true
  }

  /// `true` if the embedded provisioning profile grants `get-task-allow`
  /// (i.e. this is a Development/Ad Hoc build, not an App Store build).
  private func hasDebugEntitlement() -> Bool {
    guard let entitlements = readEmbeddedEntitlements() else { return false }
    return (entitlements["get-task-allow"] as? Bool) == true
  }

  /// `embedded.mobileprovision` is a CMS/PKCS#7-signed file, but the
  /// embedded plist payload itself is plaintext — extracting the
  /// `<?xml ... </plist>` substring directly avoids needing a full CMS
  /// parser just to read entitlements.
  private func readEmbeddedEntitlements() -> [String: Any]? {
    guard let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
          let data = FileManager.default.contents(atPath: provisioningPath),
          let plistData = extractPlist(from: data)
    else {
      return nil
    }

    let readOptions = PropertyListSerialization.ReadOptions()
    guard let parsed = try? PropertyListSerialization.propertyList(from: plistData, options: readOptions, format: nil),
          let profile = parsed as? [String: Any]
    else {
      return nil
    }
    return profile["Entitlements"] as? [String: Any]
  }

  private func extractPlist(from data: Data) -> Data? {
    guard let start = data.range(of: Data("<?xml".utf8)),
          let end = data.range(of: Data("</plist>".utf8), in: start.upperBound..<data.endIndex)
    else {
      return nil
    }
    return data.subdata(in: start.lowerBound..<end.upperBound)
  }

  private func sha256Hex(_ data: Data) -> String {
    let digest = SHA256.hash(data: data)
    return digest.map { String(format: "%02x", $0) }.joined()
  }

  enum IntegrityError: Error, LocalizedError {
    case signatureUnavailable

    var errorDescription: String? {
      switch self {
      case .signatureUnavailable:
        return "Unable to derive a signature fingerprint for this build (no embedded.mobileprovision or CodeResources found)."
      }
    }
  }
}
