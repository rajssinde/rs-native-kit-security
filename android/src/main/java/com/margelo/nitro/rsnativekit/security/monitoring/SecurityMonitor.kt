package com.margelo.nitro.rsnativekit.security.monitoring

import android.content.Context
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import com.margelo.nitro.rsnativekit.security.detectors.DeveloperModeDetector
import com.margelo.nitro.rsnativekit.security.detectors.HookDetector
import com.margelo.nitro.rsnativekit.security.detectors.IntegrityChecker
import com.margelo.nitro.rsnativekit.security.detectors.NetworkMonitor
import com.margelo.nitro.rsnativekit.security.detectors.RootDetector
import com.margelo.nitro.rsnativekit.security.detectors.ScreenMonitor
import com.margelo.nitro.rsnativekit.security.detectors.isDetected
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal data class SecurityMonitorEvent(val type: String, val message: String, val timestamp: Double)

/**
 * Drives the JS event system. VPN and screenshot signals use real OS push
 * sources (`ConnectivityManager.NetworkCallback`, a `MediaStore`
 * `ContentObserver`); everything else that doesn't have a first-class
 * Android push API (root/hook/debugger/tamper/signature state) is
 * re-evaluated on a short poll, only emitting on a false→true transition so
 * a stable device doesn't spam listeners.
 */
internal class SecurityMonitor(
  private val context: Context,
  private val rootDetector: RootDetector,
  private val hookDetector: HookDetector,
  private val integrityChecker: IntegrityChecker,
  private val networkMonitor: NetworkMonitor,
  private val screenMonitor: ScreenMonitor,
  private val developerModeDetector: DeveloperModeDetector,
  private val onEvent: (SecurityMonitorEvent) -> Unit
) {
  companion object {
    private const val POLL_INTERVAL_SECONDS = 4L
  }

  private val isRunning = AtomicBoolean(false)
  private var executor: ScheduledExecutorService? = null
  private var networkCallback: ConnectivityManager.NetworkCallback? = null
  private var screenshotObserver: ContentObserver? = null

  // Last known state, to only emit on rising edges.
  private var wasVpnConnected = false
  private var wasProxyEnabled = false
  private var wasRooted = false
  private var wasHookDetected = false
  private var wasDebuggerAttached = false
  private var wasTampered = false

  fun start() {
    if (!isRunning.compareAndSet(false, true)) return
    registerNetworkCallback()
    registerScreenshotObserver()
    startPolling()
  }

  fun stop() {
    if (!isRunning.compareAndSet(true, false)) return
    unregisterNetworkCallback()
    unregisterScreenshotObserver()
    executor?.shutdownNow()
    executor = null
  }

  private fun emit(type: String, message: String) {
    onEvent(SecurityMonitorEvent(type, message, System.currentTimeMillis().toDouble()))
  }

  // --- VPN / proxy (real push via ConnectivityManager) --------------------------------

  private fun registerNetworkCallback() {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
    val callback = object : ConnectivityManager.NetworkCallback() {
      override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
        val isVpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        if (isVpn && !wasVpnConnected) {
          emit("VPN_CONNECTED", "VPN connection detected")
        }
        wasVpnConnected = isVpn

        val isProxy = networkMonitor.isProxyEnabled()
        if (isProxy && !wasProxyEnabled) {
          emit("PROXY_ENABLED", "System proxy configuration detected")
        }
        wasProxyEnabled = isProxy
      }
    }
    try {
      cm.registerNetworkCallback(NetworkRequest.Builder().build(), callback)
      networkCallback = callback
    } catch (_: Exception) {
      networkCallback = null
    }
  }

  private fun unregisterNetworkCallback() {
    val callback = networkCallback ?: return
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    try {
      cm?.unregisterNetworkCallback(callback)
    } catch (_: Exception) {
      // already unregistered / callback never took effect
    }
    networkCallback = null
  }

  // --- Screenshots (real push via MediaStore ContentObserver) -----------------------------

  private fun registerScreenshotObserver() {
    val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
      override fun onChange(selfChange: Boolean) {
        screenMonitor.markScreenshotDetected()
        emit("SCREENSHOT", "A screenshot was captured")
      }
    }
    try {
      context.contentResolver.registerContentObserver(
        MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
        true,
        observer
      )
      screenshotObserver = observer
      screenMonitor.isObservingScreenshots = true
    } catch (_: Exception) {
      screenshotObserver = null
    }
  }

  private fun unregisterScreenshotObserver() {
    val observer = screenshotObserver ?: return
    try {
      context.contentResolver.unregisterContentObserver(observer)
    } catch (_: Exception) {
      // no-op
    }
    screenshotObserver = null
    screenMonitor.isObservingScreenshots = false
  }

  // --- Polled signals (no first-class Android push API) -------------------------------------

  private fun startPolling() {
    val scheduler = Executors.newSingleThreadScheduledExecutor()
    executor = scheduler
    scheduler.scheduleWithFixedDelay(
      { pollOnce() },
      POLL_INTERVAL_SECONDS,
      POLL_INTERVAL_SECONDS,
      TimeUnit.SECONDS
    )
  }

  private fun pollOnce() {
    try {
      val rooted = rootDetector.check().isDetected
      if (rooted && !wasRooted) emit("ROOT_DETECTED", "Root access detected on this device")
      wasRooted = rooted

      val hooked = hookDetector.checkHooks().isDetected
      if (hooked && !wasHookDetected) emit("HOOK_DETECTED", "An instrumentation/hooking framework was detected")
      wasHookDetected = hooked

      val debugger = developerModeDetector.isDebuggerAttached()
      if (debugger && !wasDebuggerAttached) emit("DEBUGGER", "A debugger attached to the app process")
      wasDebuggerAttached = debugger

      val tampered = integrityChecker.isTampered()
      if (tampered && !wasTampered) emit("TAMPER", "App tamper signal detected")
      wasTampered = tampered
    } catch (_: Exception) {
      // A single failed poll cycle must never crash the monitoring loop.
    }
  }
}