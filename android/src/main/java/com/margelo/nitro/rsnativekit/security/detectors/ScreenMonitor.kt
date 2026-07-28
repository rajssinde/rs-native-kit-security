package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.hardware.display.DisplayManager
import android.view.Display
import java.util.concurrent.atomic.AtomicLong

/**
 * Android has no direct, permission-less "is a third-party app recording my
 * screen right now" API (unlike iOS's `UIScreen.isCaptured`). [isScreenRecording]
 * is therefore a best-effort heuristic based on presentation/mirrored
 * displays; consumers that need a hard guarantee should combine this SDK
 * with `WindowManager.LayoutParams.FLAG_SECURE` on sensitive screens.
 *
 * [isScreenCaptured] reports whether a screenshot was observed recently —
 * it's driven by [markScreenshotDetected], called from the
 * `MediaStore`-observing half of the monitoring system.
 */
internal class ScreenMonitor(private val context: Context) {

  companion object {
    private const val RECENT_SCREENSHOT_WINDOW_MS = 5_000L
  }

  private val lastScreenshotAtMs = AtomicLong(0)

  fun isScreenRecording(): Boolean {
    return try {
      val displayManager =
        context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager ?: return false
      displayManager.displays.any { display ->
        display.displayId != Display.DEFAULT_DISPLAY &&
          (display.flags and Display.FLAG_PRESENTATION) != 0
      }
    } catch (_: Exception) {
      false
    }
  }

  fun isScreenCaptured(): Boolean {
    val last = lastScreenshotAtMs.get()
    if (last == 0L) return false
    return (System.currentTimeMillis() - last) < RECENT_SCREENSHOT_WINDOW_MS
  }

  fun markScreenshotDetected() {
    lastScreenshotAtMs.set(System.currentTimeMillis())
  }
}