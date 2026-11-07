package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult

/**
 * Reports overlay/tapjacking exposure. Bulk-enumerating *other* installed
 * apps' `SYSTEM_ALERT_WINDOW` grants would require the heavily Play-Store-
 * gated `QUERY_ALL_PACKAGES` permission, so this stays to what's safe for a
 * library to ship: this app's own overlay-draw capability, plus targeted
 * (single-package, always-allowed) lookups for a short list of apps known
 * to abuse overlays for tapjacking / screen-lock bypass.
 */
internal class OverlayDetector(private val context: Context) {

  fun check(): NativeDetectionResult = Detection.run {
    signal("OVERLAY_PERMISSION_GRANTED", NativeConfidence.LOW) { canThisAppDrawOverlays() }
    signal("OVERLAY_ABUSE_APP", NativeConfidence.LOW) { hasKnownOverlayAbuseAppInstalled() }
  }

  private fun canThisAppDrawOverlays(): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
    return Settings.canDrawOverlays(context)
  }

  private fun hasKnownOverlayAbuseAppInstalled(): Boolean {
    return KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.OVERLAY_ABUSE)
  }
}