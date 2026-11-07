package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.os.Build
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.util.NativeChecks
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

  fun check(): NativeDetectionResult = Detection.run {
    signal("SU_BINARY_FOUND", NativeConfidence.HIGH) {
      ShellUtils.binaryExistsOnCommonPaths("su") ||
        ShellUtils.binaryExistsOnPath("su") ||
        ShellUtils.exec(arrayOf("which", "su")) != null
    }
    // Same probe below the Java and libc layers that root-hiding tools hook.
    signal("SU_BINARY_FOUND_NATIVE", NativeConfidence.HIGH) {
      ShellUtils.COMMON_BIN_PATHS.any { NativeChecks.exists("${it}su") }
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
    // An unlocked bootloader is what Magisk, KernelSU and APatch all need, but
    // custom-ROM users and developers unlock too — hence medium. Hiding tools
    // can spoof these properties; Key Attestation reports the real state.
    signal("BOOTLOADER_UNLOCKED", NativeConfidence.MEDIUM) { isBootloaderUnlocked(NativeChecks::property) }
    // Systemless root modifies system partitions with mounts rather than
    // writes, so these name-independent signals catch Magisk, KernelSU and
    // APatch modules alike — unless DenyList/Shamiko unmounts them for this app.
    signal("SYSTEM_FILE_FROM_DATA", NativeConfidence.HIGH) {
      systemMountedFromData(parseMountInfo(ShellUtils.readProcFile("/proc/self/mountinfo")))
    }
    signal("SYSTEM_OVERLAY_MOUNT", NativeConfidence.MEDIUM) {
      hasSystemOverlayMount(parseMountInfo(ShellUtils.readProcFile("/proc/self/mountinfo")))
    }
  }

  private fun hasDangerousBuildProps(): Boolean =
    dangerousProps.any { (key, value) -> NativeChecks.property(key) == value }

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
    val mountInfo = ShellUtils.readProcFile("/proc/self/mountinfo")
    return mountInfo.lineSequence().any { line ->
      // mountinfo: <id> <parent> <major:minor> <root> <mount point> <options> ...
      val fields = line.split(' ')
      fields.size > 5 && fields[4] in SYSTEM_PARTITIONS && "rw" in fields[5].split(',')
    }
  }
}

internal val SYSTEM_PARTITIONS = setOf("/system", "/vendor", "/product", "/system_ext")

private fun isOnSystemPartition(mountPoint: String) =
  SYSTEM_PARTITIONS.any { mountPoint == it || mountPoint.startsWith("$it/") }

/** The fields of a `/proc/<pid>/mountinfo` line these checks use. */
internal data class MountEntry(val device: String, val mountPoint: String, val fsType: String)

internal fun parseMountInfo(mountInfo: String): List<MountEntry> =
  mountInfo.lineSequence().mapNotNull { line ->
    // <id> <parent> <major:minor> <root> <mount point> <options> [optional...] - <fstype> <source> <super options>
    val fields = line.split(' ')
    val fsType = line.substringAfter(" - ", "").substringBefore(' ')
    if (fields.size > 4 && fsType.isNotEmpty()) MountEntry(fields[2], fields[4], fsType) else null
  }.toList()

/**
 * A mount inside a system partition whose backing device is the `/data`
 * partition: module files bind-mounted over system files (Magisk's and
 * KernelSU's "magic mount"). Stock Android serves system files only from the
 * read-only system images.
 */
internal fun systemMountedFromData(mounts: List<MountEntry>): Boolean {
  val dataDevice = mounts.lastOrNull { it.mountPoint == "/data" }?.device ?: return false
  return mounts.any { isOnSystemPartition(it.mountPoint) && it.device == dataDevice }
}

/** overlayfs over a system partition: KernelSU's and APatch's module mounts (and `adb remount` on debug builds). */
internal fun hasSystemOverlayMount(mounts: List<MountEntry>): Boolean =
  mounts.any { isOnSystemPartition(it.mountPoint) && it.fsType == "overlay" }

/**
 * Bootloader unlocked according to the boot properties the bootloader sets.
 * `verifiedbootstate` is `orange` only when unlocked; `yellow` (a relocked
 * custom OS like GrapheneOS) is deliberately not flagged.
 */
internal fun isBootloaderUnlocked(property: (String) -> String): Boolean =
  property("ro.boot.flash.locked") == "0" ||
    property("ro.boot.vbmeta.device_state") == "unlocked" ||
    property("ro.boot.verifiedbootstate") == "orange"
