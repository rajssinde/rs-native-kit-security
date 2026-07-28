import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Multiple independent, individually-weak jailbreak signals combined —
/// mirrors the technique list used by well-known OSS jailbreak-detection
/// libraries (file existence, Cydia URL scheme, sandbox-escape write test,
/// loaded-dylib inspection, a `fork()` probe, and suspicious env vars).
final class JailbreakDetector {

  private let suspiciousPaths = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/var/stash",
    "/private/var/binpack", // checkra1n
    "/var/binpack",
    "/.bootstrapped_electra",
    "/.installed_unc0ver",
    "/jb", // rootless jailbreaks (Dopamine, palera1n) mount point
    "/usr/lib/libjailbreak.dylib",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Applications/IntelliScreen.app",
    "/Applications/SBSettings.app",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
  ]

  private let dylibMarkers = [
    "MobileSubstrate",
    "SubstrateLoader",
    "SubstrateInserter",
    "CydiaSubstrate",
    "cynject",
    "libhooker",
    "SSLKillSwitch",
    "SSLKillSwitch2"
  ]

  func isJailbroken() -> Bool {
    return !reasons().isEmpty
  }

  func reasons() -> [String] {
    var found: [String] = []

    if hasSuspiciousFiles() {
      found.append("jailbreak-associated file(s) found on disk")
    }
    if canOpenCydiaUrlScheme() {
      found.append("device can open the cydia:// URL scheme")
    }
    if canWriteOutsideSandbox() {
      found.append("app process can write outside its sandbox container")
    }
    if DylibScanner.anyLoadedImageContains(dylibMarkers) {
      found.append("a jailbreak tweak injector dylib is loaded in-process")
    }
    if ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil {
      found.append("DYLD_INSERT_LIBRARIES environment variable is set")
    }
    if !isRunningOnSimulator() && canSpawnProcess() {
      found.append("process spawn succeeded (sandbox restriction on process creation is lifted)")
    }

    return found
  }

  private func hasSuspiciousFiles() -> Bool {
    let fm = FileManager.default
    return suspiciousPaths.contains { fm.fileExists(atPath: $0) }
  }

  /// Requires `cydia` to be declared under `LSApplicationQueriesSchemes` in
  /// the host app's Info.plist to reliably return `true` (iOS 9+ policy) —
  /// this SDK cannot add that entry for the consumer app, so document it as
  /// an opt-in signal in the integration guide.
  private func canOpenCydiaUrlScheme() -> Bool {
    #if canImport(UIKit) && !os(watchOS)
    guard let url = URL(string: "cydia://package/com.example.package") else { return false }
    var result = false
    let work = { result = UIApplication.shared.canOpenURL(url) }
    if Thread.isMainThread {
      work()
    } else {
      DispatchQueue.main.sync(execute: work)
    }
    return result
    #else
    return false
    #endif
  }

  private func canWriteOutsideSandbox() -> Bool {
    let path = "/private/rs_native_kit_security_jbtest_\(UUID().uuidString).txt"
    let fm = FileManager.default
    let created = fm.createFile(atPath: path, contents: Data("jb-test".utf8))
    if created {
      try? fm.removeItem(atPath: path)
    }
    return created
  }

  private func isRunningOnSimulator() -> Bool {
    #if targetEnvironment(simulator)
    return true
    #else
    return false
    #endif
  }

  /// A jailbroken device's relaxed sandbox often allows spawning a new
  /// process to succeed; App Store sandboxing normally denies it outright.
  /// Uses `posix_spawn` rather than `fork()` — Swift marks the raw `fork()`
  /// syscall unavailable on Apple platforms (it's unsafe alongside the
  /// Objective-C runtime/GCD), and `posix_spawn` gives the same sandbox
  /// signal without that risk.
  private func canSpawnProcess() -> Bool {
    var pid: pid_t = 0
    let path = "/bin/ls"
    guard let argv0 = strdup(path) else { return false }
    var argv: [UnsafeMutablePointer<CChar>?] = [argv0, nil]
    defer { free(argv0) }

    let status = posix_spawn(&pid, path, nil, nil, &argv, environ)
    guard status == 0 else { return false }

    var waitStatus: Int32 = 0
    waitpid(pid, &waitStatus, 0)
    return true
  }
}
