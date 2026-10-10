import Foundation

/// Frida is the dominant iOS instrumentation framework in practice, so its
/// fingerprints get their own check: its default `frida-server` listen port,
/// injected dylibs, and its `DYLD_INSERT_LIBRARIES` injection vector. The
/// `hooks` umbrella adds the jailbreak hooking frameworks tweaks run on.
final class HookDetector {

  private let fridaDefaultPorts: [UInt16] = [27042, 27043]

  private let fridaDylibMarkers = [
    "FridaGadget",
    "frida-agent",
    "frida-helper"
  ]

  /// Function-hooking runtimes that jailbreak tweaks inject into apps.
  private let hookingFrameworkMarkers = [
    "MobileSubstrate",
    "CydiaSubstrate",
    "SubstrateLoader",
    "libhooker",
    "libsubstitute",
    "libellekit",
    "ElleKit"
  ]

  func checkFrida() -> NativeDetectionResult {
    Detection.run { d in
      d.signal("FRIDA_DYLIB", .high) { DylibScanner.anyLoadedImageContains(fridaDylibMarkers) }
      d.signal("FRIDA_DYLD_INSERT", .high) {
        ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"]?
          .localizedCaseInsensitiveContains("frida") == true
      }
      // Something listening on Frida's default ports — frida-server may also use custom ports.
      d.signal("FRIDA_PORT_OPEN", .medium) { fridaDefaultPorts.contains { isPortOpen(port: $0) } }
    }
  }

  /// Umbrella check: Frida plus the jailbreak hooking frameworks.
  func checkHooks(frida: NativeDetectionResult? = nil) -> NativeDetectionResult {
    Detection.run { d in
      d.include(frida ?? checkFrida())
      d.signal("HOOKING_FRAMEWORK_DYLIB", .high) { DylibScanner.anyLoadedImageContains(hookingFrameworkMarkers) }
    }
  }

  private func isPortOpen(port: UInt16, host: String = "127.0.0.1", timeoutMs: Int = 200) -> Bool {
    let sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    guard sock >= 0 else { return false }
    defer { close(sock) }

    // Non-blocking connect with a short manual timeout via select(), so a
    // filtered/closed port never stalls the whole `scan()` call.
    let flags = fcntl(sock, F_GETFL, 0)
    _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)

    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr.s_addr = inet_addr(host)

    let connectResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
      ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
        connect(sock, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }

    if connectResult == 0 {
      return true
    }
    guard errno == EINPROGRESS else { return false }

    var writeSet = fd_set()
    fdZero(&writeSet)
    fdSet(sock, &writeSet)
    var timeout = timeval(tv_sec: 0, tv_usec: Int32(timeoutMs * 1000))

    let selectResult = select(sock + 1, nil, &writeSet, nil, &timeout)
    guard selectResult > 0 else { return false }

    var socketError: Int32 = 0
    var length = socklen_t(MemoryLayout<Int32>.size)
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &socketError, &length)
    return socketError == 0
  }

  // `fd_set` has no Swift-native bit-twiddling helpers.
  private func fdZero(_ set: inout fd_set) {
    set.fds_bits = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
  }

  private func fdSet(_ fd: Int32, _ set: inout fd_set) {
    let intOffset = Int(fd) / 32
    let bitOffset = Int(fd) % 32
    let mask: Int32 = 1 << bitOffset
    withUnsafeMutablePointer(to: &set.fds_bits) { ptr in
      ptr.withMemoryRebound(to: Int32.self, capacity: 32) { bits in
        bits[intOffset] |= mask
      }
    }
  }
}
