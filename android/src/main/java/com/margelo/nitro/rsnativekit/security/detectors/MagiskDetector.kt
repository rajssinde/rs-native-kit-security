package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.content.pm.PackageManager
import com.margelo.nitro.rsnativekit.security.util.ShellUtils

/** Magisk-specific signals, separate from generic root heuristics so `checks.magisk` stays precise. */
internal class MagiskDetector(private val context: Context) {

  private val magiskPaths = arrayOf(
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk",
    "/data/adb/magisk.db",
    "/data/adb/modules",
    "/data/magisk.apk",
    "/data/adb/magisk_simple"
  )

  fun isDetected(): Boolean {
    return isMagiskAppInstalled() ||
      magiskPaths.any { path -> ShellUtils.readFileOrNull(path) != null || java.io.File(path).exists() } ||
      ShellUtils.binaryExistsOnCommonPaths("magisk") ||
      ShellUtils.exec(arrayOf("magisk", "-v")) != null
  }

  private fun isMagiskAppInstalled(): Boolean {
    return try {
      context.packageManager.getPackageInfo("com.topjohnwu.magisk", 0)
      true
    } catch (_: PackageManager.NameNotFoundException) {
      false
    }
  }
}
