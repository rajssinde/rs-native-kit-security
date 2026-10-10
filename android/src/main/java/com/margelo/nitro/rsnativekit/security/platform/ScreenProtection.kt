package com.margelo.nitro.rsnativekit.security.platform

import android.app.Activity
import android.os.Build
import android.view.WindowManager

/**
 * Prevention, not just detection:
 * - Screen-capture protection sets `FLAG_SECURE`: screenshots and recordings
 *   of the app come out black, and it's hidden in the recents switcher.
 * - Overlay protection hides other apps' overlay windows while this app is
 *   in front (Android 12+, `HIDE_OVERLAY_WINDOWS`) and drops touches that pass
 *   through an overlay (`filterTouchesWhenObscured`), blocking tapjacking.
 *
 * Both stay applied to every activity the app shows until disabled.
 */
internal class ScreenProtection(private val activities: ActivityTracker) : ActivityTracker.Listener {

  @Volatile
  private var captureProtected = false

  @Volatile
  private var overlayProtected = false

  init {
    activities.addListener(this)
  }

  fun setCaptureProtection(enabled: Boolean) {
    captureProtected = enabled
    applyToCurrent()
  }

  fun setOverlayProtection(enabled: Boolean) {
    overlayProtected = enabled
    applyToCurrent()
  }

  override fun onActivityStarted(activity: Activity) = apply(activity)

  private fun applyToCurrent() {
    val activity = activities.current ?: return // applied when the next activity starts
    activity.runOnUiThread { apply(activity) }
  }

  private fun apply(activity: Activity) {
    val window = activity.window ?: return
    if (captureProtected) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
      window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      window.setHideOverlayWindows(overlayProtected)
    }
    window.decorView.filterTouchesWhenObscured = overlayProtected
  }
}
