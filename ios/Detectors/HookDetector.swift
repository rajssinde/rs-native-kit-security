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
      d.signal("FRIDA_THREAD", .high) {
        try threadNames().contains { name in fridaThreadMarkers.contains { name.contains($0) } }
      }
      // frida-agent / frida-gadget export these even when the library file is renamed.
      d.signal("FRIDA_SYMBOL", .high) {
        fridaSymbols.contains { dlsym(rtldDefault, $0) != nil }
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
      #if !targetEnvironment(simulator)
      // A jailbreak file the raw system call sees but FileManager doesn't can
      // only mean FileManager is hooked to hide it — proof of a hiding tweak.
      d.signal("FILE_API_HOOKED", .high) {
        JailbreakDetector.suspiciousPaths.contains { path in
          rs_raw_path_exists(path) == 1 && !FileManager.default.fileExists(atPath: path)
        }
      }
      #endif
    }
  }

  private let fridaThreadMarkers = ["gum-js-loop", "gmain", "gdbus", "frida"]
  private let fridaSymbols = ["frida_agent_main", "gum_init_embedded"]
  private let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT

  /// Names of every pthread in this process (Frida names its threads).
  private func threadNames() throws -> [String] {
    var threads: thread_act_array_t?
    var count: mach_msg_type_number_t = 0
    guard task_threads(mach_task_self_, &threads, &count) == KERN_SUCCESS, let threads else {
      throw DetectionError("task_threads failed")
    }
    defer {
      vm_deallocate(
        mach_task_self_,
        vm_address_t(UInt(bitPattern: threads)),
        vm_size_t(Int(count) * MemoryLayout<thread_t>.stride)
      )
    }
    var names: [String] = []
    for index in 0..<Int(count) {
      let thread = threads[index]
      if let pthread = pthread_from_mach_thread_np(thread) {
        var buffer = [CChar](repeating: 0, count: 64)
        if pthread_getname_np(pthread, &buffer, buffer.count) == 0 {
          names.append(String(cString: buffer))
        }
      }
      mach_port_deallocate(mach_task_self_, thread)
    }
    return names
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
