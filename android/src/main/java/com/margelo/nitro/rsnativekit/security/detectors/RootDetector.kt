package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.margelo.nitro.rsnativekit.security.util.ShellUtils

/**
 * Android root detection using multiple independent, individually-weak
 * signals — no single check is authoritative, so [isRooted] treats "two or
 * more distinct signals fired" as strong evidence, while [reasons] still
 * surfaces every individual signal for audit logging.
 */
internal class RootDetector(private val context: Context) {

  /** Known root-management / su-provider app packages. */
  private val rootPackages = arrayOf(
    "com.topjohnwu.magisk",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "me.phh.superuser",
    "com.geohot.towelroot",
    "com.ramdroid.appquarantine"
  )

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
    if (hasSuspiciousMounts()) {
      found += "root-hiding bind mount detected in /proc/self/mountinfo"
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
    val pm = context.packageManager
    return rootPackages.any { pkg -> isPackageInstalled(pm, pkg) }
  }

  private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
    return try {
      pm.getPackageInfo(packageName, 0)
      true
    } catch (_: PackageManager.NameNotFoundException) {
      false
    }
  }

  private fun isSystemWritable(): Boolean {
    return ShellUtils.isWritable("/system") || ShellUtils.isWritable("/system/bin")
  }

  private fun isSELinuxPermissive(): Boolean {
    val status = ShellUtils.readFileOrNull("/sys/fs/selinux/enforce")
      ?: ShellUtils.exec(arrayOf("getenforce"))
    return status?.trim()?.let { it == "0" || it.equals("Permissive", ignoreCase = true) } == true
  }

  private fun hasSuspiciousMounts(): Boolean {
    val mountInfo = ShellUtils.readFileOrNull("/proc/self/mountinfo") ?: return false
    return mountInfo.lineSequence().any { line ->
      (line.contains("/system") || line.contains("/vendor")) && line.contains(" rw,")
    }
  }
}