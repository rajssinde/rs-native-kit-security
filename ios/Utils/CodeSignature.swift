import Foundation

/// Reads the entitlements embedded in this app's own code signature.
///
/// iOS has no public API for an app to inspect its own signing identity, and
/// App Store binaries are re-signed with Apple's certificate, so hashing a
/// certificate (as Android does) proves nothing. What *does* identify who
/// built the app is the Team ID baked into the signed entitlements
/// (`application-identifier` = `TEAMID.bundle.id`): re-signing an IPA with a
/// different account necessarily changes it. The entitlements blob lives in
/// the executable's `LC_CODE_SIGNATURE` superblob, which we parse here.
enum CodeSignature {
  private static let lcCodeSignature: UInt32 = 0x1d
  private static let mhMagic64: UInt32 = 0xfeed_facf
  private static let fatMagic: UInt32 = 0xcafe_babe
  private static let fatMagic64: UInt32 = 0xcafe_babf
  private static let superBlobMagic: UInt32 = 0xfade_0cc0
  private static let entitlementsBlobMagic: UInt32 = 0xfade_7171
  private static let entitlementsSlot: UInt32 = 5

  /// Team ID of whoever signed the running app.
  static func teamIdentifier() throws -> String {
    guard let path = Bundle.main.executablePath else {
      throw DetectionError("executable path unavailable")
    }
    let binary = try Data(contentsOf: URL(fileURLWithPath: path), options: .alwaysMapped)
    return try teamIdentifier(fromEntitlements: entitlementsPlist(fromMachO: binary))
  }

  static func teamIdentifier(fromEntitlements plist: Data) throws -> String {
    guard let entitlements = try PropertyListSerialization.propertyList(from: plist, options: PropertyListSerialization.ReadOptions(), format: nil) as? [String: Any] else {
      throw DetectionError("entitlements are not a dictionary")
    }
    if let team = entitlements["com.apple.developer.team-identifier"] as? String, isTeamIdentifier(team) {
      return team
    }
    // iOS names the key `application-identifier`; macOS `com.apple.application-identifier`.
    let appId = (entitlements["application-identifier"] ?? entitlements["com.apple.application-identifier"]) as? String
    if let appId, let dot = appId.firstIndex(of: "."), isTeamIdentifier(String(appId[..<dot])) {
      return String(appId[..<dot])
    }
    throw DetectionError("no team identifier in the code-signature entitlements")
  }

  /// Team IDs are exactly 10 uppercase letters/digits; Apple platform binaries
  /// use a bare bundle ID (`com.apple.Safari`) with no team prefix.
  static func isTeamIdentifier(_ value: String) -> Bool {
    value.count == 10 && value.allSatisfy { ($0.isUppercase || $0.isNumber) && $0.isASCII }
  }

  /// Extracts the entitlements plist from a (thin or fat) Mach-O binary.
  static func entitlementsPlist(fromMachO binary: Data) throws -> Data {
    let reader = ByteReader(binary)
    let sliceOffset = try thinSliceOffset(reader)

    guard try reader.uint32LE(sliceOffset) == mhMagic64 else {
      throw DetectionError("not a 64-bit Mach-O binary")
    }
    let commandCount = Int(try reader.uint32LE(sliceOffset + 16))
    var commandOffset = sliceOffset + 32 // sizeof(mach_header_64)

    for _ in 0..<commandCount {
      let command = try reader.uint32LE(commandOffset)
      let commandSize = Int(try reader.uint32LE(commandOffset + 4))
      guard commandSize >= 8 else { throw DetectionError("malformed load command") }
      if command == lcCodeSignature {
        let signatureOffset = sliceOffset + Int(try reader.uint32LE(commandOffset + 8))
        return try entitlements(inSuperBlobAt: signatureOffset, reader: reader)
      }
      commandOffset += commandSize
    }
    throw DetectionError("binary has no code signature")
  }

  private static func thinSliceOffset(_ reader: ByteReader) throws -> Int {
    let magic = try reader.uint32BE(0)
    guard magic == fatMagic || magic == fatMagic64 else { return 0 }

    #if arch(arm64)
    let wantedCpuType: UInt32 = 0x0100_000c // CPU_TYPE_ARM64
    #else
    let wantedCpuType: UInt32 = 0x0100_0007 // CPU_TYPE_X86_64
    #endif
    let is64 = magic == fatMagic64
    let archSize = is64 ? 32 : 20
    let archCount = Int(try reader.uint32BE(4))
    for index in 0..<archCount {
      let archOffset = 8 + index * archSize
      if try reader.uint32BE(archOffset) == wantedCpuType {
        return is64 ? Int(try reader.uint64BE(archOffset + 8)) : Int(try reader.uint32BE(archOffset + 8))
      }
    }
    throw DetectionError("no slice for the running architecture")
  }

  private static func entitlements(inSuperBlobAt offset: Int, reader: ByteReader) throws -> Data {
    guard try reader.uint32BE(offset) == superBlobMagic else {
      throw DetectionError("code signature is not a superblob")
    }
    let blobCount = Int(try reader.uint32BE(offset + 8))
    for index in 0..<blobCount {
      let entry = offset + 12 + index * 8
      guard try reader.uint32BE(entry) == entitlementsSlot else { continue }
      let blobOffset = offset + Int(try reader.uint32BE(entry + 4))
      guard try reader.uint32BE(blobOffset) == entitlementsBlobMagic else {
        throw DetectionError("entitlements slot has an unexpected blob type")
      }
      let blobLength = Int(try reader.uint32BE(blobOffset + 4))
      guard blobLength >= 8 else { throw DetectionError("malformed entitlements blob") }
      return try reader.bytes(blobOffset + 8, count: blobLength - 8)
    }
    throw DetectionError("code signature carries no entitlements")
  }
}

/// Bounds-checked integer reads over an untrusted binary.
private struct ByteReader {
  let data: Data

  init(_ data: Data) { self.data = data }

  func bytes(_ offset: Int, count: Int) throws -> Data {
    guard offset >= 0, count >= 0, offset <= data.count - count else {
      throw DetectionError("read past the end of the binary")
    }
    let start = data.startIndex + offset
    return data.subdata(in: start..<(start + count))
  }

  func uint32BE(_ offset: Int) throws -> UInt32 {
    try bytes(offset, count: 4).reduce(0) { ($0 << 8) | UInt32($1) }
  }

  func uint32LE(_ offset: Int) throws -> UInt32 {
    try bytes(offset, count: 4).reversed().reduce(0) { ($0 << 8) | UInt32($1) }
  }

  func uint64BE(_ offset: Int) throws -> UInt64 {
    try bytes(offset, count: 8).reduce(0) { ($0 << 8) | UInt64($1) }
  }
}
