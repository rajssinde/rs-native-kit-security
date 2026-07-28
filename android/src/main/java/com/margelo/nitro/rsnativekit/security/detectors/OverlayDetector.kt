package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

/**
 * Reports overlay/tapjacking exposure. Bulk-enumerating *other* installed
 * apps' `SYSTEM_ALERT_WINDOW` grants would require the heavily Play-Store-
 * gated `QUERY_ALL_PACKAGES` permission, so this stays to what's safe for a
 * library to ship: this app's own overlay-draw capability, plus targeted
 * (single-package, always-allowed) lookups for a short list of apps known
 * to abuse overlays for tapjacking / screen-lock bypass.
 */
internal class OverlayDetector(private val context: Context) {

  private val knownOverlayAbusePackages = arrayOf(
    "com.baiduAppSearch.searchbox", // historical overlay-abuse offenders used in public research
    "com.gtp.nextlauncher.overlay",
    "com.android.systemui.overlay.fake"
  )

  fun hasOverlayPermission(): Boolean {
    return canThisAppDrawOverlays() || hasKnownOverlayAbuseAppInstalled()
  }

  private fun canThisAppDrawOverlays(): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
    return try {
      Settings.canDrawOverlays(context)
    } catch (_: Exception) {
      false
    }
  }

  private fun hasKnownOverlayAbuseAppInstalled(): Boolean {
    val pm = context.packageManager
    return knownOverlayAbusePackages.any { pkg ->
      try {
        pm.getPackageInfo(pkg, 0)
        true
      } catch (_: PackageManager.NameNotFoundException) {
        false
      }
    }
  }
}