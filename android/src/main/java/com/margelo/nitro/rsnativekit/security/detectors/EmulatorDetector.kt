package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.os.Build
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import java.io.File

/**
 * Detects the generic Android Emulator/AVD plus the common third-party
 * emulators (Genymotion, BlueStacks, LDPlayer, Nox, MEmu) via `Build.*`
 * fingerprints, well-known emulator-only files, and installed packages.
 */
internal class EmulatorDetector(private val context: Context) {

  private val qemuFiles = arrayOf(
    "/dev/qemu_pipe",
    "/dev/socket/qemud",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemu-props"
  )

  fun check(): NativeDetectionResult = Detection.run {
    signal("EMULATOR_BUILD_FINGERPRINT", NativeConfidence.MEDIUM) { hasEmulatorBuildFingerprint() }
    signal("EMULATOR_QEMU_FILES", NativeConfidence.HIGH) { qemuFiles.any { File(it).exists() } }
    signal("EMULATOR_APP", NativeConfidence.MEDIUM) {
      KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.EMULATORS)
    }
    signal("EMULATOR_TELEPHONY", NativeConfidence.LOW) { hasEmulatorTelephonyProperties() }
  }

  private fun hasEmulatorBuildFingerprint(): Boolean {
    val fingerprint = Build.FINGERPRINT.lowercase()
    val model = Build.MODEL.lowercase()
    val manufacturer = Build.MANUFACTURER.lowercase()
    val hardware = Build.HARDWARE.lowercase()
    val product = Build.PRODUCT.lowercase()
    val brand = Build.BRAND.lowercase()

    return fingerprint.startsWith("generic") ||
      fingerprint.startsWith("unknown") ||
      fingerprint.contains("vbox") ||
      fingerprint.contains("test-keys") && model.contains("sdk") ||
      model.contains("google_sdk") ||
      model.contains("emulator") ||
      model.contains("android sdk built for x86") ||
      manufacturer.contains("genymotion") ||
      manufacturer == "unknown" && brand.startsWith("generic") ||
      hardware.contains("goldfish") ||
      hardware.contains("ranchu") ||
      hardware.contains("vbox86") ||
      product.contains("sdk_gphone") ||
      product.contains("google_sdk") ||
      product.contains("sdk_x86") ||
      product.contains("vbox86p") ||
      Build.HOST.startsWith("Build")
  }

  private fun hasEmulatorTelephonyProperties(): Boolean {
    // Stock AVDs consistently report these placeholder telephony identifiers.
    // Devices without telephony (tablets, some TVs) have no TelephonyManager: not an emulator signal.
    val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? android.telephony.TelephonyManager
      ?: return false
    return tm.networkOperatorName?.lowercase() == "android"
  }
}