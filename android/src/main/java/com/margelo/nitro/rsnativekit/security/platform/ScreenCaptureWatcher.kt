package com.margelo.nitro.rsnativekit.security.platform

import android.app.Activity
import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.view.WindowManager
import java.util.Collections
import java.util.concurrent.Executor
import java.util.function.Consumer

/**
 * Screenshot and screen-recording push signals, using the most accurate
 * source each Android version offers:
 *
 * - Android 14+: `Activity.ScreenCaptureCallback` — the OS reports
 *   screenshots of this app's window directly (`DETECT_SCREEN_CAPTURE`).
 * - Android 15+: `WindowManager.addScreenRecordingCallback` — whether this
 *   app is visible in an active screen recording (`DETECT_SCREEN_RECORDING`).
 * - Older versions: a `MediaStore` observer that only reports an image once
 *   it's confirmed to be a screenshot (name/path). Confirming needs media read
 *   permission; without it nothing is reported, rather than reporting every
 *   camera photo or download as a screenshot.
 */
internal class ScreenCaptureWatcher(
  private val context: Context,
  private val activities: ActivityTracker,
  private val onScreenshot: () -> Unit,
  private val onRecordingChanged: (visible: Boolean) -> Unit
) : ActivityTracker.Listener {

  private val mainExecutor: Executor = Executor { Handler(Looper.getMainLooper()).post(it) }
  private val registeredActivities: MutableSet<Activity> = Collections.synchronizedSet(mutableSetOf())
  private var screenCaptureCallback: Any? = null
  private var recordingCallback: Consumer<Int>? = null
  private var mediaObserver: ContentObserver? = null
  private var lastScreenshotId = -1L

  /** Starts watching; returns `true` if any screenshot source is active. */
  fun start(): Boolean {
    startRecordingCallback()
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      screenCaptureCallback = Activity.ScreenCaptureCallback { onScreenshot() }
      activities.addListener(this)
      true
    } else {
      startMediaObserver()
    }
  }

  fun stop() {
    activities.removeListener(this)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      val callback = screenCaptureCallback as? Activity.ScreenCaptureCallback
      val activities = synchronized(registeredActivities) { registeredActivities.toList() }
      activities.forEach { activity ->
        activity.runOnUiThread { callback?.let { unregister(activity, it) } }
      }
    }
    registeredActivities.clear()
    screenCaptureCallback = null
    stopRecordingCallback()
    mediaObserver?.let { context.contentResolver.unregisterContentObserver(it) }
    mediaObserver = null
  }

  // --- Android 14+: screenshot callback ---------------------------------------------

  override fun onActivityStarted(activity: Activity) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
    val callback = screenCaptureCallback as? Activity.ScreenCaptureCallback ?: return
    if (!registeredActivities.add(activity)) return
    try {
      activity.registerScreenCaptureCallback(mainExecutor, callback)
    } catch (_: SecurityException) {
      registeredActivities.remove(activity) // DETECT_SCREEN_CAPTURE removed from the merged manifest
    }
  }

  override fun onActivityStopped(activity: Activity) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
    val callback = screenCaptureCallback as? Activity.ScreenCaptureCallback ?: return
    if (registeredActivities.remove(activity)) unregister(activity, callback)
  }

  private fun unregister(activity: Activity, callback: Activity.ScreenCaptureCallback) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
    try {
      activity.unregisterScreenCaptureCallback(callback)
    } catch (_: Exception) {
      // already unregistered
    }
  }

  // --- Android 15+: screen recording callback --------------------------------------

  private fun startRecordingCallback() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) return
    val windowManager = context.getSystemService(WindowManager::class.java) ?: return
    val callback = Consumer<Int> { state ->
      onRecordingChanged(state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
    }
    try {
      val initial = windowManager.addScreenRecordingCallback(mainExecutor, callback)
      recordingCallback = callback
      onRecordingChanged(initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
    } catch (_: SecurityException) {
      // DETECT_SCREEN_RECORDING removed from the merged manifest
    }
  }

  private fun stopRecordingCallback() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) return
    val callback = recordingCallback ?: return
    context.getSystemService(WindowManager::class.java)?.removeScreenRecordingCallback(callback)
    recordingCallback = null
  }

  // --- Older Android: confirmed MediaStore screenshots --------------------------------

  private fun startMediaObserver(): Boolean {
    val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
      override fun onChange(selfChange: Boolean, uri: Uri?) {
        if (isNewScreenshot(uri)) onScreenshot()
      }
    }
    return try {
      context.contentResolver.registerContentObserver(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, true, observer)
      mediaObserver = observer
      true
    } catch (_: Exception) {
      false
    }
  }

  @Suppress("DEPRECATION") // DATA is the only path column before Android 10
  private fun isNewScreenshot(uri: Uri?): Boolean {
    val pathColumn = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      MediaStore.Images.Media.RELATIVE_PATH
    } else {
      MediaStore.Images.Media.DATA
    }
    val projection = arrayOf(MediaStore.Images.Media._ID, MediaStore.Images.Media.DISPLAY_NAME, pathColumn, MediaStore.Images.Media.DATE_ADDED)
    val target = uri?.takeIf { it.lastPathSegment?.toLongOrNull() != null }
      ?: MediaStore.Images.Media.EXTERNAL_CONTENT_URI
    return try {
      context.contentResolver.query(target, projection, null, null, "${MediaStore.Images.Media.DATE_ADDED} DESC")?.use { cursor ->
        if (!cursor.moveToFirst()) return false
        val id = cursor.getLong(0)
        val name = cursor.getString(1).orEmpty()
        val path = cursor.getString(2).orEmpty()
        val addedSecondsAgo = System.currentTimeMillis() / 1000 - cursor.getLong(3)
        val isScreenshot = (name + path).contains("screenshot", ignoreCase = true) && addedSecondsAgo in 0..10
        // One screenshot triggers several change notifications; report it once.
        if (!isScreenshot || id == lastScreenshotId) return false
        lastScreenshotId = id
        true
      } ?: false
    } catch (_: SecurityException) {
      false // no media read permission: can't confirm, so don't report
    }
  }
}
