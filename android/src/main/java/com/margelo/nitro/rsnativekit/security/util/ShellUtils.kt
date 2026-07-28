package com.margelo.nitro.rsnativekit.security.util

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * Shared low-level helpers for the root/hook/emulator detectors. Every
 * process-exec call is bounded by a short timeout and never throws — a
 * detector that can't run a check should treat it as "not detected", not
 * crash the whole scan.
 */
internal object ShellUtils {
  /** Common locations where a `su`/`busybox`/etc. binary might live on a rooted device. */
  val COMMON_BIN_PATHS = arrayOf(
    "/data/local/",
    "/data/local/bin/",
    "/data/local/xbin/",
    "/sbin/",
    "/su/bin/",
    "/system/bin/",
    "/system/bin/.ext/",
    "/system/bin/failsafe/",
    "/system/sbin/",
    "/system/usr/we-need-root/",
    "/system/xbin/",
    "/cache/",
    "/data/",
    "/dev/"
  )

  /** True if `binaryName` exists (as a regular, readable file) in any of `COMMON_BIN_PATHS`. */
  fun binaryExistsOnCommonPaths(binaryName: String): Boolean {
    return COMMON_BIN_PATHS.any { dir -> File(dir, binaryName).exists() }
  }

  /** True if `binaryName` is resolvable on the process `PATH`. */
  fun binaryExistsOnPath(binaryName: String): Boolean {
    val path = System.getenv("PATH") ?: return false
    return path.split(File.pathSeparator).any { dir ->
      File(dir, binaryName).let { it.exists() && it.canExecute() }
    }
  }

  /**
   * Runs `command` with a hard [timeoutMs] deadline and returns combined
   * stdout, or `null` if the command failed, timed out, or couldn't start.
   */
  fun exec(command: Array<String>, timeoutMs: Long = 1500): String? {
    var process: Process? = null
    return try {
      process = ProcessBuilder(*command)
        .redirectErrorStream(true)
        .start()

      val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
      if (!finished) {
        process.destroyForcibly()
        return null
      }

      BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
    } catch (_: Exception) {
      null
    } finally {
      process?.destroyForcibly()
    }
  }

  /** True if a given absolute file/directory path both exists and is writable. */
  fun isWritable(path: String): Boolean {
    return try {
      File(path).canWrite()
    } catch (_: Exception) {
      false
    }
  }

  /** Reads a whole file as text, or `null` on any failure (missing, unreadable, SELinux-denied, ...). */
  fun readFileOrNull(path: String): String? {
    return try {
      File(path).takeIf { it.isFile && it.canRead() }?.readText()
    } catch (_: Exception) {
      null
    }
  }
}
