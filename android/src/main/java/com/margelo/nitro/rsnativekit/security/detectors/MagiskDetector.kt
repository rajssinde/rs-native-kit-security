package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.util.NativeChecks
import com.margelo.nitro.rsnativekit.security.util.ShellUtils
import java.io.File

/** Magisk-specific signals, separate from generic root heuristics so `checks.magisk` stays precise. */
internal class MagiskDetector(private val context: Context) {

  /**
   * Legacy/well-known Magisk paths. On modern Android, SELinux blocks an
   * untrusted app from even stat()-ing `/data/adb` and `/cache`, so these
   * only fire on old Magisk versions or permissive/misconfigured devices —
   * the mount-table signal is the one that works for a normal app.
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

  fun check(): NativeDetectionResult = Detection.run {
    signal("MAGISK_APP", NativeConfidence.MEDIUM) {
      KnownPackages.isInstalled(context.packageManager, KnownPackages.MAGISK)
    }
    signal("MAGISK_FILES", NativeConfidence.HIGH) {
      magiskPaths.any { File(it).exists() || (NativeChecks.isAvailable && NativeChecks.exists(it)) }
    }
    signal("MAGISK_BINARY", NativeConfidence.HIGH) {
      ShellUtils.binaryExistsOnCommonPaths("magisk") || ShellUtils.exec(arrayOf("magisk", "-v")) != null
    }
    signal("MAGISK_MOUNTS", NativeConfidence.HIGH) { hasMagiskMounts() }
  }

  /**
   * Magisk's systemless overlays show up in this process's mount table unless
   * DenyList/Zygisk hiding unmounts them for this app: its tmpfs mounts are
   * named "magisk", and Magisk 26+ mounts its tmpfs at `/debug_ramdisk`
   * (an empty, unmounted directory on stock devices).
   */
  private fun hasMagiskMounts(): Boolean {
    val mountInfo = ShellUtils.readProcFile("/proc/self/mountinfo")
    return mountInfo.lineSequence().any { line ->
      // mountinfo: <id> <parent> <major:minor> <root> <mount point> <options> ... - <fstype> <source> ...
      val fields = line.split(' ')
      val source = line.substringAfter(" - ", "").split(' ').getOrNull(1)
      fields.getOrNull(4) == "/debug_ramdisk" || source.equals("magisk", ignoreCase = true)
    }
  }
}
