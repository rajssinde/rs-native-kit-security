package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.os.Build
import com.margelo.nitro.rsnativekit.security.util.ShellUtils

/**
 * Android root detection using multiple independent, individually-weak
 * signals. [isRooted] is `true` when any signal fires; [reasons] surfaces
 * every individual signal for audit logging.
 */
internal class RootDetector(private val context: Context) {

  private val dangerousProps = mapOf(
    "ro.debuggable" to "1",
    "ro.secure" to "0"
  )

  fun isRooted(): Boolean = reasons().isNotEmpty()

  /** Human-readable reason for every root signal that fired, for `scan()`'s `reasons[]`. */
  fun reasons(): List<String> {
    val found = mutableListOf<String>()

    if (ShellUtils.binaryExistsOnCommonPaths("su") || ShellUtils.binaryExistsOnPath("su")) {
      found += "su binary found on device"
    }
    if (canExecuteSu()) {
      found += "su binary is executable"
    }
    if (Build.TAGS?.contains("test-keys") == true) {
      found += "Build.TAGS contains test-keys (custom/dev-signed ROM)"
    }
    if (hasDangerousBuildProps()) {
      found += "ro.debuggable=1 or ro.secure=0 system property detected"
    }
    if (hasRootManagementApp()) {
      found += "a known root-management app is installed"
    }
    if (isSystemWritable()) {
      found += "/system partition is writable (should be read-only)"
    }
    if (isSELinuxPermissive()) {
      found += "SELinux is permissive (should be enforcing)"
    }
    if (hasReadWriteSystemMount()) {
      found += "a /system, /vendor or /product partition is mounted read-write"
    }

    return found
  }

  private fun canExecuteSu(): Boolean {
    return ShellUtils.exec(arrayOf("which", "su")) != null ||
      ShellUtils.exec(arrayOf("su", "-c", "id")) != null
  }

  private fun hasDangerousBuildProps(): Boolean {
    val output = ShellUtils.exec(arrayOf("getprop")) ?: return false
    return dangerousProps.any { (key, value) ->
      output.contains("[$key]: [$value]")
    }
  }

  private fun hasRootManagementApp(): Boolean {
    return KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.ROOT_MANAGERS)
  }

  private fun isSystemWritable(): Boolean {
    return ShellUtils.isWritable("/system") || ShellUtils.isWritable("/system/bin")
  }

  private fun isSELinuxPermissive(): Boolean {
    val status = ShellUtils.readFileOrNull("/sys/fs/selinux/enforce")
      ?: ShellUtils.exec(arrayOf("getenforce"))
    return status?.trim()?.let { it == "0" || it.equals("Permissive", ignoreCase = true) } == true
  }

  private val systemMountPoints = setOf("/system", "/vendor", "/product", "/system_ext")

  /**
   * Stock devices always mount the system partitions read-only; a `rw` remount
   * is a classic root modification. Matches the exact mount point and mount
   * options fields only — a substring match also hits legitimately writable
   * mounts like `/mnt/vendor/persist` or `/data/vendor`.
   */
  private fun hasReadWriteSystemMount(): Boolean {
    val mountInfo = ShellUtils.readFileOrNull("/proc/self/mountinfo") ?: return false
    return mountInfo.lineSequence().any { line ->
      // mountinfo: <id> <parent> <major:minor> <root> <mount point> <options> ...
      val fields = line.split(' ')
      fields.size > 5 && fields[4] in systemMountPoints && "rw" in fields[5].split(',')
    }
  }
}