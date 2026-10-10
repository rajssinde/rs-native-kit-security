import CryptoKit
import Foundation
import NitroModules
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// Apple App Attest (iOS 14+). The device's Secure Enclave generates a key,
/// Apple attests it, and later assertions prove requests come from that
/// genuine, unmodified app instance. Attestation objects and assertions are
/// opaque to the app — only your server verifies them (see the `server/`
/// verifier package), so nothing here makes a trust decision on the device.
final class AppAttest {

  func isSupported() -> Bool {
    #if canImport(DeviceCheck)
    if #available(iOS 14.0, *) {
      return DCAppAttestService.shared.isSupported
    }
    #endif
    return false
  }

  func generateKey() -> Promise<String> {
    let promise = Promise<String>()
    #if canImport(DeviceCheck)
    guard #available(iOS 14.0, *), DCAppAttestService.shared.isSupported else {
      promise.reject(withError: unsupported())
      return promise
    }
    DCAppAttestService.shared.generateKey { keyId, error in
      if let keyId {
        promise.resolve(withResult: keyId)
      } else {
        promise.reject(withError: error ?? DetectionError("generateKey returned no key"))
      }
    }
    #else
    promise.reject(withError: unsupported())
    #endif
    return promise
  }

  /// `clientDataHash` = SHA-256 of `challenge` (UTF-8), which the server recomputes.
  func attestKey(_ keyId: String, challenge: String) -> Promise<String> {
    let promise = Promise<String>()
    #if canImport(DeviceCheck)
    guard #available(iOS 14.0, *), DCAppAttestService.shared.isSupported else {
      promise.reject(withError: unsupported())
      return promise
    }
    DCAppAttestService.shared.attestKey(keyId, clientDataHash: sha256(challenge)) { attestation, error in
      if let attestation {
        promise.resolve(withResult: attestation.base64EncodedString())
      } else {
        promise.reject(withError: error ?? DetectionError("attestKey returned no attestation"))
      }
    }
    #else
    promise.reject(withError: unsupported())
    #endif
    return promise
  }

  /// `clientDataHash` = SHA-256 of `clientData` (UTF-8), which the server recomputes.
  func generateAssertion(_ keyId: String, clientData: String) -> Promise<String> {
    let promise = Promise<String>()
    #if canImport(DeviceCheck)
    guard #available(iOS 14.0, *), DCAppAttestService.shared.isSupported else {
      promise.reject(withError: unsupported())
      return promise
    }
    DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: sha256(clientData)) { assertion, error in
      if let assertion {
        promise.resolve(withResult: assertion.base64EncodedString())
      } else {
        promise.reject(withError: error ?? DetectionError("generateAssertion returned no assertion"))
      }
    }
    #else
    promise.reject(withError: unsupported())
    #endif
    return promise
  }

  private func sha256(_ value: String) -> Data {
    Data(SHA256.hash(data: Data(value.utf8)))
  }

  private func unsupported() -> Error {
    // The Simulator, and devices without a Secure Enclave, don't support App Attest.
    DetectionError("App Attest is not supported on this device (requires iOS 14+ on a physical device)")
  }
}
