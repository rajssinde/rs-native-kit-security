import Foundation
import ObjectiveC
import Security

/// Enforces public-key pinning on React Native's networking stack.
///
/// `RCTHTTPRequestHandler` is the `NSURLSession` delegate behind `fetch`,
/// `XMLHttpRequest` and image loading, and it doesn't handle authentication
/// challenges itself. This *adds* `URLSession:didReceiveChallenge:completionHandler:`
/// to that class (it never replaces existing code): for pinned hosts the
/// server trust must pass normal validation **and** contain a pinned key;
/// everything else gets default handling. If a future React Native version
/// implements the method itself, enabling fails loudly instead of silently
/// not pinning. RN creates its session lazily on the first request, so this
/// must run before then.
enum SslPinning {
  private static let lock = NSLock()
  private static var domains: [NativePinnedDomain] = []
  private static var installed = false

  static func enable(_ newDomains: [NativePinnedDomain]) throws {
    lock.lock()
    defer { lock.unlock() }
    guard !installed else {
      throw DetectionError("SSL pinning is already enabled; it can only be configured once per app launch")
    }
    guard !newDomains.isEmpty else { throw DetectionError("at least one pinned domain is required") }
    for domain in newDomains where domain.pins.count < 2 {
      throw DetectionError("\(domain.hostname) needs at least two pins (one backup)")
    }
    guard let handlerClass = NSClassFromString("RCTHTTPRequestHandler") else {
      throw DetectionError("RCTHTTPRequestHandler not found; can't attach pinning to React Native networking")
    }

    let selector = NSSelectorFromString("URLSession:didReceiveChallenge:completionHandler:")
    let block: @convention(block) (
      AnyObject, URLSession, URLAuthenticationChallenge,
      @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) -> Void = { _, _, challenge, completion in
      handle(challenge, completion: completion)
    }
    // v = void return, @ = self, : = _cmd, @ session, @ challenge, @? block
    guard class_addMethod(handlerClass, selector, imp_implementationWithBlock(block), "v@:@@@?") else {
      throw DetectionError("React Native's networking already handles TLS challenges; pinning was not installed")
    }
    domains = newDomains
    installed = true
  }

  private static func pinnedDomain(for host: String) -> NativePinnedDomain? {
    let host = host.lowercased()
    lock.lock()
    defer { lock.unlock() }
    return domains.first { domain in
      host == domain.hostname || (domain.includeSubdomains && host.hasSuffix("." + domain.hostname))
    }
  }

  private static func handle(
    _ challenge: URLAuthenticationChallenge,
    completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    let space = challenge.protectionSpace
    guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let domain = pinnedDomain(for: space.host)
    else {
      completion(.performDefaultHandling, nil)
      return
    }
    guard let trust = space.serverTrust, SecTrustEvaluateWithError(trust, nil) else {
      completion(.cancelAuthenticationChallenge, nil) // fails normal validation
      return
    }
    let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
    let pinned = Set(domain.pins)
    if chain.contains(where: { SpkiHash.pin(for: $0).map(pinned.contains) == true }) {
      completion(.useCredential, URLCredential(trust: trust))
    } else {
      completion(.cancelAuthenticationChallenge, nil) // valid certificate, but no pinned key
    }
  }
}
