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
   * stdout, or `null` if the command exited non-zero, timed out, or couldn't
   * start. A non-zero exit must count as failure: e.g. `which su` on a stock
   * device runs fine but exits 1 with no output, and treating that as success
   * made every device look rooted.
   */
  fun exec(command: Array<String>, timeoutMs: Long = 1500): String? {
    var process: Process? = null
    return try {
      val proc = ProcessBuilder(*command)
        .redirectErrorStream(true)
        .start()
      process = proc

      // Drain output concurrently: reading only after waitFor() deadlocks once
      // the output fills the pipe buffer (e.g. a long `getprop` dump).
      val output = StringBuilder()
      val reader = Thread {
        try {
          BufferedReader(InputStreamReader(proc.inputStream)).use { output.append(it.readText()) }
        } catch (_: Exception) {
          // stream closed by destroyForcibly() on timeout
        }
      }.apply {
        isDaemon = true
        start()
      }

      if (!proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
        return null
      }
      reader.join(timeoutMs)
      if (reader.isAlive || proc.exitValue() != 0) {
        return null
      }

      output.toString()
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

  /**
   * Reads a file that should always be readable by the app (e.g. `/proc/self/maps`),
   * throwing if it isn't — so a detector reports the signal as failed, not clean.
   */
  fun readFile(path: String): String = File(path).readText()

  /** Reads a whole file as text, or `null` on any failure (missing, unreadable, SELinux-denied, ...). */
  fun readFileOrNull(path: String): String? {
    return try {
      File(path).takeIf { it.isFile && it.canRead() }?.readText()
    } catch (_: Exception) {
      null
    }
  }
}
