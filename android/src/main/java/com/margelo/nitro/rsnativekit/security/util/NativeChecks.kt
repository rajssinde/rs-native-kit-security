package com.margelo.nitro.rsnativekit.security.util

/**
 * File probes implemented in C++ (`cpp/native-checks.cpp`) that bypass hooks
 * on the Java file APIs and, on arm64, on libc. Throws
 * [IllegalStateException] when the native library isn't loaded (e.g. JVM unit
 * tests), so a detector reports the signal as failed rather than clean.
 */
internal object NativeChecks {

  val isAvailable: Boolean = try {
    System.loadLibrary("rsnativekit_security")
    true
  } catch (_: Throwable) {
    false
  }

  fun exists(path: String): Boolean {
    check(isAvailable) { "native checks unavailable" }
    return pathExists(path)
  }

  /** File contents, or `null` when it can't be opened. */
  fun read(path: String): String? {
    check(isAvailable) { "native checks unavailable" }
    return readFile(path)
  }

  @JvmStatic
  private external fun pathExists(path: String): Boolean

  @JvmStatic
  private external fun readFile(path: String): String?
}
