import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Multiple independent, individually-weak jailbreak signals combined:
/// jailbreak files (via FileManager, libc and a raw system call), symlinked
/// system directories, jailbreak app URL schemes, a sandbox-escape write test,
/// injected tweak libraries, a process-spawn probe, and suspicious env vars.
/// Covers rootful (checkra1n, unc0ver) and rootless (Dopamine, palera1n)
/// jailbreaks — rootless ones keep everything under `/var/jb`.
final class JailbreakDetector {

  static let suspiciousPaths = [
    // Rootless jailbreaks (Dopamine, palera1n rootless, XinaA15)
    "/var/jb",
    "/private/var/jb",
    "/var/jb/.installed_dopamine",
    "/var/jb/.procursus_strapped",
    "/var/jb/usr/bin/su",
    "/var/jb/usr/lib/TweakInject",
    "/var/jb/Applications/Sileo.app",
    "/var/containers/Bundle/Application/.jbroot",
    "/cores/binpack", // palera1n
    "/private/preboot/jb",
    // Rootful jailbreaks and package managers
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Filza.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/TweakInject",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/bin/ssh",
    "/usr/libexec/sftp-server",
    "/usr/libexec/cydia",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/var/stash",
    "/private/var/binpack", // checkra1n
    "/var/binpack",
    "/.bootstrapped_electra",
    "/.installed_unc0ver",
    "/.procursus_strapped",
    "/jb",
    "/usr/lib/libjailbreak.dylib",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Applications/IntelliScreen.app",
    "/Applications/SBSettings.app",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
  ]

  /// Directories rootful jailbreaks historically replaced with symlinks to free system space.
  private let symlinkedDirectories = [
    "/Applications",
    "/Library/Ringtones",
    "/Library/Wallpaper",
    "/usr/arm-apple-darwin9",
    "/usr/include",
    "/usr/libexec",
    "/usr/share"
  ]

  /// URL schemes of jailbreak package managers and tools. Each must be listed
  /// under `LSApplicationQueriesSchemes` in the app's Info.plist to be checkable.
  private let urlSchemes = ["cydia", "sileo", "zbra", "filza", "undecimus", "activator"]

  /// Tweak injectors, plus the jailbreak-*hiding* tweaks themselves.
  private let dylibMarkers = [
    "MobileSubstrate",
    "SubstrateLoader",
    "SubstrateInserter",
    "CydiaSubstrate",
    "TweakInject",
    "libellekit",
    "libsubstitute",
    "cynject",
    "libhooker",
    "RocketBootstrap",
    "SSLKillSwitch",
    "Shadow.dylib",
    "ABypass",
    "FlyJB",
    "LibertyLite",
    "Choicy"
  ]

  func check() -> NativeDetectionResult {
    #if targetEnvironment(simulator)
    // The Simulator runs on the Mac's filesystem (which has /usr/sbin/sshd,
    // /usr/libexec/sftp-server, ...) without the device sandbox, so every
    // signal here would fire. `checkEmulator()` already reports the Simulator.
    return Detection.unsupported()
    #else
    return Detection.run { d in
      d.signal("JAILBREAK_FILES", .high) { hasSuspiciousFiles() }
      d.signal("SYMLINKED_SYSTEM_DIRECTORY", .medium) { hasSymlinkedSystemDirectory() }
      d.signal("JAILBREAK_URL_SCHEME", .medium) { canOpenJailbreakUrlScheme() }
      d.signal("SANDBOX_WRITE_ESCAPE", .high) { canWriteOutsideSandbox() }
      d.signal("TWEAK_INJECTOR_DYLIB", .high) { DylibScanner.anyLoadedImageContains(dylibMarkers) }
      #if !DEBUG
      // Xcode sets DYLD_INSERT_LIBRARIES itself for sanitizers / debugging tools.
      d.signal("DYLD_INSERT_LIBRARIES_SET", .medium) {
        ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil
      }
      #endif
      d.signal("PROCESS_SPAWN_ALLOWED", .high) { canSpawnProcess() }
    }
    #endif
  }

  func isJailbroken() -> Bool {
    check().isDetected
  }

  /// Any of three independent probes: hiding tweaks have to defeat all of them.
  private func hasSuspiciousFiles() -> Bool {
    let fm = FileManager.default
    return Self.suspiciousPaths.contains { path in
      fm.fileExists(atPath: path) || access(path, F_OK) == 0 || rs_raw_path_exists(path) == 1
    }
  }

  private func hasSymlinkedSystemDirectory() -> Bool {
    symlinkedDirectories.contains { path in
      var info = stat()
      return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }
  }

  private func canOpenJailbreakUrlScheme() -> Bool {
    #if canImport(UIKit) && !os(watchOS)
    let urls = urlSchemes.compactMap { URL(string: "\($0)://") }
    var result = false
    let work = { result = urls.contains { UIApplication.shared.canOpenURL($0) } }
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
