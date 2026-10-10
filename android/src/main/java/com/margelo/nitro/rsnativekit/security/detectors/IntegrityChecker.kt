package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.margelo.nitro.rsnativekit.security.BuildConfig
import java.io.File
import java.security.MessageDigest

/**
 * Signature/APK integrity + a zero-config tamper heuristic.
 *
 * `isTampered()` needs to work without any app-supplied "known good" hash
 * (it's part of the parameterless `scan()`), so it can only check for
 * generic tamper/repackaging *symptoms* (debuggable release build, missing
 * installer identity). For an authoritative check, apps should call
 * [verifyAppSignature] or [verifyApkIntegrity] with a hash pinned at build
 * time.
 *
 * React Native compiles this library with the same build type as the host
 * app, so [BuildConfig.DEBUG] tells us whether the *app* is a debug build.
 * Debug builds are debuggable and `adb install`-ed by design, so both
 * symptoms are only meaningful in release builds.
 */
internal class IntegrityChecker(private val context: Context) {

  fun isTampered(): Boolean {
    if (BuildConfig.DEBUG) return false
    return isDebuggableReleaseBuild() || hasUntrustedInstaller()
  }

  /** A release-compiled app carrying `FLAG_DEBUGGABLE` was almost certainly repackaged. */
  private fun isDebuggableReleaseBuild(): Boolean {
    return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
  }

  private val trustedInstallers = setOf(
    "com.android.vending", // Google Play
    "com.amazon.venezia", // Amazon Appstore
    "com.sec.android.app.samsungapps", // Galaxy Store
    "com.huawei.appmarket"
  )

  /**
   * Flags apps with *no* installer identity at all (typical of a raw
   * `adb install`/direct APK sideload of a repackaged app). Enterprise
   * MDM-distributed installs use a real installer package too (the MDM
   * agent), so this doesn't penalize legitimate internal distribution.
   */
  private fun hasUntrustedInstaller(): Boolean {
    val installer = getInstallerPackageName() ?: return true
    return installer.isBlank()
  }

  private fun getInstallerPackageName(): String? {
    return try {
      val pm = context.packageManager
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        pm.getInstallSourceInfo(context.packageName).installingPackageName
      } else {
        @Suppress("DEPRECATION")
        pm.getInstallerPackageName(context.packageName)
      }
    } catch (_: Exception) {
      null
    }
  }

  /** Not currently used to compute [isTampered], but kept for future stricter policies. */
  internal fun isInstalledFromTrustedStore(): Boolean {
    return getInstallerPackageName() in trustedInstallers
  }

  fun getAppSignatureHash(): String {
    val digestBytes = getSigningCertificateBytes()
      ?: throw IllegalStateException("Unable to read the app's signing certificate")
    return sha256Hex(digestBytes)
  }

  fun verifyAppSignature(expectedSignatureHash: String): Boolean {
    return try {
      getAppSignatureHash().equals(expectedSignatureHash, ignoreCase = true)
    } catch (_: Exception) {
      false
    }
  }

  fun verifyApkIntegrity(expectedSha256: String): Boolean {
    val apkPath = context.applicationInfo.sourceDir
    val digest = sha256HexOfFile(apkPath) ?: return false
    return digest.equals(expectedSha256, ignoreCase = true)
  }

  @Suppress("DEPRECATION")
  private fun getSigningCertificateBytes(): ByteArray? {
    return try {
      val pm = context.packageManager
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signingInfo = info.signingInfo ?: return null
        val signatures = if (signingInfo.hasMultipleSigners()) {
          signingInfo.apkContentsSigners
        } else {
          signingInfo.signingCertificateHistory
        }
        signatures?.firstOrNull()?.toByteArray()
      } else {
        val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        info.signatures?.firstOrNull()?.toByteArray()
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString("") { "%02x".format(it) }
  }

  private fun sha256HexOfFile(path: String): String? {
    return try {
      val digest = MessageDigest.getInstance("SHA-256")
      File(path).inputStream().use { input ->
        val buffer = ByteArray(8192)
        var read: Int
        while (input.read(buffer).also { read = it } != -1) {
          digest.update(buffer, 0, read)
        }
      }
      digest.digest().joinToString("") { "%02x".format(it) }
    } catch (_: Exception) {
      null
    }
  }
}