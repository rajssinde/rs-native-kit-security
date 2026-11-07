package com.margelo.nitro.rsnativekit.security.detectors

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootSignalsTest {

  // Trimmed from a stock Android 15 device: system images on dm devices, /data on its own.
  private val stockMountInfo = """
    1 0 253:5 / / ro,relatime shared:1 - erofs /dev/block/dm-5 ro
    25 1 253:6 / /vendor ro,relatime shared:5 - erofs /dev/block/dm-6 ro
    26 1 253:7 / /product ro,relatime shared:6 - erofs /dev/block/dm-7 ro
    27 1 253:8 / /system_ext ro,relatime shared:7 - erofs /dev/block/dm-8 ro
    40 1 0:22 / /apex rw,nosuid,nodev,noexec,relatime shared:12 - tmpfs tmpfs rw,seclabel
    90 1 254:44 / /data rw,nosuid,nodev,noatime shared:40 - f2fs /dev/block/dm-44 rw,seclabel
    91 90 254:44 /media /storage/emulated rw,nosuid,nodev,noatime shared:41 - f2fs /dev/block/dm-44 rw
  """.trimIndent()

  private fun withLine(line: String) = "$stockMountInfo\n$line"

  @Test
  fun `parses device, mount point and filesystem type`() {
    val mounts = parseMountInfo(stockMountInfo)
    assertEquals(7, mounts.size)
    assertEquals(MountEntry("254:44", "/data", "f2fs"), mounts[5])
  }

  @Test
  fun `skips lines without the fstype separator`() {
    assertTrue(parseMountInfo("garbage\n\n").isEmpty())
  }

  @Test
  fun `a stock mount table has no systemless-root mounts`() {
    val mounts = parseMountInfo(stockMountInfo)
    assertFalse(systemMountedFromData(mounts))
    assertFalse(hasSystemOverlayMount(mounts))
  }

  @Test
  fun `a module file bind-mounted from data over a system file is detected`() {
    // Magisk/KernelSU magic mount: /data/adb/modules/<id>/system/bin/foo -> /system/bin/foo
    val mounts = parseMountInfo(
      withLine("300 1 254:44 /adb/modules/hosts/system/etc/hosts /system/etc/hosts ro,relatime - f2fs /dev/block/dm-44 rw")
    )
    assertTrue(systemMountedFromData(mounts))
  }

  @Test
  fun `data-backed mounts outside system partitions are not flagged`() {
    val mounts = parseMountInfo(withLine("301 1 254:44 /misc/vold /mnt/vendor/persist rw - f2fs /dev/block/dm-44 rw"))
    assertFalse(systemMountedFromData(mounts))
  }

  @Test
  fun `a path that only starts with a partition name is not that partition`() {
    val mounts = parseMountInfo(withLine("302 1 254:44 / /systemfoo rw - f2fs /dev/block/dm-44 rw"))
    assertFalse(systemMountedFromData(mounts))
  }

  @Test
  fun `no data mount means nothing to compare against`() {
    assertFalse(systemMountedFromData(parseMountInfo("1 0 253:5 / /system ro - erofs /dev/block/dm-5 ro")))
  }

  @Test
  fun `overlayfs over a system partition is detected`() {
    // KernelSU / APatch module overlay
    val mounts = parseMountInfo(withLine("310 25 0:91 / /vendor ro,relatime - overlay KSU ro,lowerdir=/data/adb/modules/x/vendor:/vendor"))
    assertTrue(hasSystemOverlayMount(mounts))
  }

  @Test
  fun `bootloader unlocked from any of the boot properties`() {
    fun props(vararg pairs: Pair<String, String>): (String) -> String = { pairs.toMap()[it] ?: "" }
    assertTrue(isBootloaderUnlocked(props("ro.boot.flash.locked" to "0")))
    assertTrue(isBootloaderUnlocked(props("ro.boot.vbmeta.device_state" to "unlocked")))
    assertTrue(isBootloaderUnlocked(props("ro.boot.verifiedbootstate" to "orange")))
  }

  @Test
  fun `locked stock and relocked custom OS are not flagged`() {
    fun props(vararg pairs: Pair<String, String>): (String) -> String = { pairs.toMap()[it] ?: "" }
    val stock = props(
      "ro.boot.flash.locked" to "1",
      "ro.boot.vbmeta.device_state" to "locked",
      "ro.boot.verifiedbootstate" to "green"
    )
    assertFalse(isBootloaderUnlocked(stock))
    assertFalse(isBootloaderUnlocked(props("ro.boot.flash.locked" to "1", "ro.boot.verifiedbootstate" to "yellow")))
    assertFalse(isBootloaderUnlocked(props())) // properties unset
  }
}
