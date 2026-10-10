import CryptoKit
import Foundation
import Security

/// SHA-256 of a certificate's SubjectPublicKeyInfo (base64) — the value in an
/// HPKP-style `sha256/<base64>=` pin, identical to
/// `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
///
/// `SecKeyCopyExternalRepresentation` returns only the raw key (PKCS#1 for
/// RSA, an X9.63 point for EC), so the SPKI DER is rebuilt around it.
enum SpkiHash {
  private static let rsaAlgorithm: [UInt8] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  ]
  private static let ecPublicKeyOid: [UInt8] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
  private static let curveOids: [Int: [UInt8]] = [
    256: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], // prime256v1
    384: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], // secp384r1
    521: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], // secp521r1
  ]

  static func pin(for certificate: SecCertificate) -> String? {
    guard let key = SecCertificateCopyKey(certificate),
          let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
          let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
          let type = attributes[kSecAttrKeyType] as? String,
          let bits = attributes[kSecAttrKeySizeInBits] as? Int
    else { return nil }

    let algorithm: [UInt8]
    if type == (kSecAttrKeyTypeRSA as String) {
      algorithm = rsaAlgorithm
    } else if type == (kSecAttrKeyTypeECSECPrimeRandom as String), let curve = curveOids[bits] {
      algorithm = der(0x30, ecPublicKeyOid + curve)
    } else {
      return nil
    }
    let spki = der(0x30, algorithm + der(0x03, [0x00] + [UInt8](raw)))
    return Data(SHA256.hash(data: Data(spki))).base64EncodedString()
  }

  private static func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
    var length: [UInt8]
    if content.count < 0x80 {
      length = [UInt8(content.count)]
    } else {
      var value = content.count
      var bytes: [UInt8] = []
      while value > 0 {
        bytes.insert(UInt8(value & 0xff), at: 0)
        value >>= 8
      }
      length = [0x80 | UInt8(bytes.count)] + bytes
    }
    return [tag] + length + content
  }
}
