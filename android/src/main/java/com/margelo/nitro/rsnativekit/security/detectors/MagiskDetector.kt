package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import com.margelo.nitro.rsnativekit.security.util.ShellUtils

/** Magisk-specific signals, separate from generic root heuristics so `checks.magisk` stays precise. */
internal class MagiskDetector(private val context: Context) {

  /**
   * Legacy/well-known Magisk paths. On modern Android, SELinux blocks an
   * untrusted app from even stat()-ing `/data/adb` and `/cache`, so these
   * only fire on old Magisk versions or permissive/misconfigured devices —
   * [hasMagiskMounts] is the signal that works for a normal app.
   */
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
      ShellUtils.exec(arrayOf("magisk", "-v")) != null ||
      hasMagiskMounts()
  }

  /**
   * Magisk's systemless overlays show up in this process's mount table unless
   * DenyList/Zygisk hiding unmounts them for this app: its tmpfs mounts are
   * named "magisk", and Magisk 26+ mounts its tmpfs at `/debug_ramdisk`
   * (an empty, unmounted directory on stock devices).
   */
  private fun hasMagiskMounts(): Boolean {
    val mountInfo = ShellUtils.readFileOrNull("/proc/self/mountinfo") ?: return false
    return mountInfo.lineSequence().any { line ->
      // mountinfo: <id> <parent> <major:minor> <root> <mount point> <options> ... - <fstype> <source> ...
      val fields = line.split(' ')
      val source = line.substringAfter(" - ", "").split(' ').getOrNull(1)
      fields.getOrNull(4) == "/debug_ramdisk" || source.equals("magisk", ignoreCase = true)
    }
  }

  private fun isMagiskAppInstalled(): Boolean {
    return KnownPackages.isInstalled(context.packageManager, KnownPackages.MAGISK)
  }
}
