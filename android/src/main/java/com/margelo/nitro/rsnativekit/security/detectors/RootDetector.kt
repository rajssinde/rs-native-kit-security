package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.os.Build
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.util.ShellUtils

/**
 * Android root detection using multiple independent, individually-weak
 * signals. The result is `detected` when any signal fires; `reasons` lists
 * every signal that did, for audit logging.
 *
 * `su` is only located, never executed: running `su` on a rooted device pops
 * a superuser-grant prompt in front of the user.
 */
internal class RootDetector(private val context: Context) {

  private val dangerousProps = mapOf(
    "ro.debuggable" to "1",
    "ro.secure" to "0"
  )

  private val systemMountPoints = setOf("/system", "/vendor", "/product", "/system_ext")

  fun check(): NativeDetectionResult = Detection.run {
    signal("SU_BINARY_FOUND", NativeConfidence.HIGH) {
      ShellUtils.binaryExistsOnCommonPaths("su") ||
        ShellUtils.binaryExistsOnPath("su") ||
        ShellUtils.exec(arrayOf("which", "su")) != null
    }
    signal("TEST_KEYS_BUILD", NativeConfidence.LOW) { Build.TAGS?.contains("test-keys") == true }
    signal("DANGEROUS_BUILD_PROPS", NativeConfidence.MEDIUM) { hasDangerousBuildProps() }
    signal("ROOT_MANAGER_APP", NativeConfidence.MEDIUM) {
      KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.ROOT_MANAGERS)
    }
    signal("SYSTEM_WRITABLE", NativeConfidence.HIGH) {
      ShellUtils.isWritable("/system") || ShellUtils.isWritable("/system/bin")
    }
    signal("SELINUX_PERMISSIVE", NativeConfidence.MEDIUM) { isSELinuxPermissive() }
    signal("SYSTEM_MOUNTED_RW", NativeConfidence.HIGH) { hasReadWriteSystemMount() }
  }

  private fun hasDangerousBuildProps(): Boolean {
    val output = ShellUtils.exec(arrayOf("getprop"))
      ?: throw IllegalStateException("getprop failed")
    return dangerousProps.any { (key, value) ->
      output.contains("[$key]: [$value]")
    }
  }

  private fun isSELinuxPermissive(): Boolean {
    // Unreadable on most modern devices (SELinux policy) — fall back to getenforce,
    // and treat "no answer from either" as not detected rather than an error.
    val status = ShellUtils.readFileOrNull("/sys/fs/selinux/enforce")
      ?: ShellUtils.exec(arrayOf("getenforce"))
    return status?.trim()?.let { it == "0" || it.equals("Permissive", ignoreCase = true) } == true
  }

  /**
   * Stock devices always mount the system partitions read-only; a `rw` remount
   * is a classic root modification. Matches the exact mount point and mount
   * options fields only — a substring match also hits legitimately writable
   * mounts like `/mnt/vendor/persist` or `/data/vendor`.
   */
  private fun hasReadWriteSystemMount(): Boolean {
    val mountInfo = ShellUtils.readFile("/proc/self/mountinfo")
    return mountInfo.lineSequence().any { line ->
      // mountinfo: <id> <parent> <major:minor> <root> <mount point> <options> ...
      val fields = line.split(' ')
      fields.size > 5 && fields[4] in systemMountPoints && "rw" in fields[5].split(',')
    }
  }
}
