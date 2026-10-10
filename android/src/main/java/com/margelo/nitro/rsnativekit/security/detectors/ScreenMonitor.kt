package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.hardware.display.DisplayManager
import android.view.Display
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.NativeDetectionStatus
import java.util.concurrent.atomic.AtomicLong

/**
 * Android has no direct, permission-less "is a third-party app recording my
 * screen right now" API (unlike iOS's `UIScreen.isCaptured`). [checkScreenRecording]
 * is therefore a best-effort heuristic based on presentation/mirrored
 * displays; consumers that need a hard guarantee should combine this SDK
 * with `WindowManager.LayoutParams.FLAG_SECURE` on sensitive screens.
 *
 * [checkScreenCapture] reports whether a screenshot was observed recently —
 * it's driven by [markScreenshotDetected], called from the
 * `MediaStore`-observing half of the monitoring system, so it can only
 * observe anything while monitoring is running.
 */
internal class ScreenMonitor(private val context: Context) {

  companion object {
    private const val RECENT_SCREENSHOT_WINDOW_MS = 5_000L
  }

  private val lastScreenshotAtMs = AtomicLong(0)

  /** Set by `SecurityMonitor` while its screenshot observer is registered. */
  @Volatile
  var isObservingScreenshots = false

  fun checkScreenRecording(): NativeDetectionResult = Detection.run {
    signal("PRESENTATION_DISPLAY", NativeConfidence.LOW) {
      val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
        ?: throw IllegalStateException("DisplayManager unavailable")
      displayManager.displays.any { display ->
        display.displayId != Display.DEFAULT_DISPLAY &&
          (display.flags and Display.FLAG_PRESENTATION) != 0
      }
    }
  }

  fun checkScreenCapture(): NativeDetectionResult {
    val last = lastScreenshotAtMs.get()
    if (last != 0L && (System.currentTimeMillis() - last) < RECENT_SCREENSHOT_WINDOW_MS) {
      return NativeDetectionResult(
        NativeDetectionStatus.DETECTED,
        arrayOf("SCREENSHOT_RECENT"),
        NativeConfidence.MEDIUM,
        null
      )
    }
    return NativeDetectionResult(
      NativeDetectionStatus.NOT_DETECTED,
      emptyArray(),
      if (isObservingScreenshots) NativeConfidence.MEDIUM else NativeConfidence.LOW,
      if (isObservingScreenshots) null else "screenshot monitoring is not running; call addListener() to observe screenshots"
    )
  }

  fun markScreenshotDetected() {
    lastScreenshotAtMs.set(System.currentTimeMillis())
  }
}
