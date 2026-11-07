package com.margelo.nitro.rsnativekit.security.platform

import android.app.Activity
import android.app.Application
import android.os.Bundle
import java.lang.ref.WeakReference
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Tracks the started activity and notifies listeners as activities start
 * and stop, so per-window features (FLAG_SECURE, screenshot callbacks) are
 * re-applied to every new activity — including ones recreated on rotation.
 */
internal class ActivityTracker(application: Application, initial: Activity?) :
  Application.ActivityLifecycleCallbacks {

  interface Listener {
    fun onActivityStarted(activity: Activity) {}
    fun onActivityStopped(activity: Activity) {}
  }

  private val listeners = CopyOnWriteArraySet<Listener>()

  @Volatile
  private var currentRef = WeakReference(initial)

  val current: Activity?
    get() = currentRef.get()?.takeUnless { it.isFinishing || it.isDestroyed }

  init {
    application.registerActivityLifecycleCallbacks(this)
  }

  /** Adds [listener] and immediately replays the current activity to it. */
  fun addListener(listener: Listener) {
    listeners += listener
    current?.let { activity -> activity.runOnUiThread { listener.onActivityStarted(activity) } }
  }

  fun removeListener(listener: Listener) {
    listeners -= listener
  }

  override fun onActivityStarted(activity: Activity) {
    currentRef = WeakReference(activity)
    listeners.forEach { it.onActivityStarted(activity) }
  }

  override fun onActivityStopped(activity: Activity) {
    listeners.forEach { it.onActivityStopped(activity) }
  }

  override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
  override fun onActivityResumed(activity: Activity) {}
  override fun onActivityPaused(activity: Activity) {}
  override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
  override fun onActivityDestroyed(activity: Activity) {}
}
