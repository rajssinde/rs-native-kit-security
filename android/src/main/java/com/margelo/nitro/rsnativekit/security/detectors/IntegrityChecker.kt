package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import com.margelo.nitro.rsnativekit.security.BuildConfig
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.NativeDetectionStatus
import java.io.File
import java.security.MessageDigest

/**
 * Signature/APK integrity + a zero-config tamper heuristic.
 *
 * [checkTampering] needs to work without any app-supplied "known good" hash
 * (it's part of the parameterless `scan()`), so it can only check for
 * generic tamper/repackaging *symptoms* (debuggable release build, missing
 * installer identity). For an authoritative check, apps configure expected
 * signing-certificate hashes, which [checkSignature] verifies.
 *
 * React Native compiles this library with the same build type as the host
 * app, so [BuildConfig.DEBUG] tells us whether the *app* is a debug build.
 * Debug builds are debuggable and `adb install`-ed by design, so both
 * symptoms are only meaningful in release builds.
 */
internal class IntegrityChecker(private val context: Context) {

  fun checkTampering(): NativeDetectionResult {
    if (BuildConfig.DEBUG) {
      return NativeDetectionResult(NativeDetectionStatus.UNSUPPORTED, arrayOf("DEBUG_BUILD"), NativeConfidence.HIGH, null)
    }
    return Detection.run {
      // A release-compiled app carrying FLAG_DEBUGGABLE was almost certainly repackaged.
      signal("DEBUGGABLE_RELEASE_BUILD", NativeConfidence.HIGH) {
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
      }
      // No installer identity at all: a raw `adb install` / direct sideload, the usual way a
      // repackaged APK is installed. Store, MDM and Firebase App Distribution installs all
      // record an installer package.
      signal("NO_INSTALLER_RECORDED", NativeConfidence.MEDIUM) { getInstallerPackageName().isNullOrBlank() }
    }
  }

  fun isTampered(): Boolean = checkTampering().isDetected

  private fun getInstallerPackageName(): String? {
    val pm = context.packageManager
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      pm.getInstallSourceInfo(context.packageName).installingPackageName
    } else {
      @Suppress("DEPRECATION")
      pm.getInstallerPackageName(context.packageName)
    }
  }

  /** SHA-256 (lowercase hex) of the app's current signing certificate. */
  fun getAppSignatureHash(): String = currentSignerHashes().first()

  /**
   * `detected` = a current signer's certificate hash matches none of
   * [expectedHashes]. Hashes may be hex (with or without `:` separators, as
   * `keytool`/`apksigner` print them) or base64.
   */
  fun checkSignature(expectedHashes: Array<String>): NativeDetectionResult {
    val provided = expectedHashes.map { it.trim() }.filter { it.isNotEmpty() }
    if (provided.isEmpty()) return Detection.notConfigured("SIGNATURE_HASH_NOT_CONFIGURED")
    // A malformed configured hash is a config bug: report it, don't treat it as "not configured".
    val expected = provided.map { normalizeHash(it) ?: return invalidHash(it) }.toSet()
    return Detection.run {
      signal("SIGNATURE_MISMATCH", NativeConfidence.HIGH) {
        currentSignerHashes().any { it !in expected }
      }
    }
  }

  fun checkApkIntegrity(expectedSha256: String): NativeDetectionResult {
    if (expectedSha256.isBlank()) return Detection.notConfigured("APK_HASH_NOT_CONFIGURED")
    val expected = normalizeHash(expectedSha256) ?: return invalidHash(expectedSha256)
    return Detection.run {
      signal("APK_HASH_MISMATCH", NativeConfidence.HIGH) {
        sha256HexOfFile(context.applicationInfo.sourceDir) != expected
      }
    }
  }

  /**
   * Hashes of the certificates currently signing the APK. Uses the *current*
   * signers: `signingCertificateHistory` starts with the original, pre-rotation
   * certificate, which would make every app that rotated its key look tampered.
   */
  @Suppress("DEPRECATION")
  private fun currentSignerHashes(): List<String> {
    val pm = context.packageManager
    val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        .signingInfo?.apkContentsSigners
    } else {
      pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
    }
    val hashes = signatures?.map { sha256Hex(it.toByteArray()) }.orEmpty()
    if (hashes.isEmpty()) throw IllegalStateException("Unable to read the app's signing certificate")
    return hashes
  }

  private fun invalidHash(raw: String): NativeDetectionResult =
    Detection.failed(IllegalArgumentException("\"$raw\" is not a SHA-256 hash (expected 64 hex chars or base64)"))

  private fun normalizeHash(raw: String): String? {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return null
    val hex = trimmed.replace(":", "").replace(" ", "")
    if (hex.length == 64 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return hex.lowercase()
    return try {
      val bytes = Base64.decode(trimmed, Base64.DEFAULT)
      if (bytes.size == 32) bytes.toHex() else null
    } catch (_: IllegalArgumentException) {
      null
    }
  }

  private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

  private fun sha256HexOfFile(path: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    File(path).inputStream().use { input ->
      val buffer = ByteArray(8192)
      var read: Int
      while (input.read(buffer).also { read = it } != -1) {
        digest.update(buffer, 0, read)
      }
    }
    return digest.digest().toHex()
  }

  private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
