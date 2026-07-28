package com.margelo.nitro.rsnativekit.security

import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.Promise
import com.margelo.nitro.rsnativekit.security.detectors.BusyBoxDetector
import com.margelo.nitro.rsnativekit.security.detectors.DeveloperModeDetector
import com.margelo.nitro.rsnativekit.security.detectors.EmulatorDetector
import com.margelo.nitro.rsnativekit.security.detectors.HookDetector
import com.margelo.nitro.rsnativekit.security.detectors.IntegrityChecker
import com.margelo.nitro.rsnativekit.security.detectors.MagiskDetector
import com.margelo.nitro.rsnativekit.security.detectors.NetworkMonitor
import com.margelo.nitro.rsnativekit.security.detectors.OverlayDetector
import com.margelo.nitro.rsnativekit.security.detectors.RootDetector
import com.margelo.nitro.rsnativekit.security.detectors.ScreenMonitor
import com.margelo.nitro.rsnativekit.security.monitoring.SecurityMonitor

/**
 * Composition root: implements the Nitro `Security` spec by delegating to
 * the individual detectors under `detectors/`, and the event system to
 * `monitoring/SecurityMonitor`. Every detector does its own I/O
 * (file/process/PackageManager access), so every method here runs via
 * `Promise.parallel` — detection work never touches the JS/UI thread.
 */
@DoNotStrip
class Security : HybridSecuritySpec() {

  private val context by lazy {
    NitroModules.applicationContext
      ?: throw IllegalStateException(
        "[@rs-native-kit/security] No ReactApplicationContext is available yet."
      )
  }

  private val rootDetector by lazy { RootDetector(context) }
  private val magiskDetector by lazy { MagiskDetector(context) }
  private val busyBoxDetector by lazy { BusyBoxDetector() }
  private val emulatorDetector by lazy { EmulatorDetector(context) }
  private val hookDetector by lazy { HookDetector(context) }
  private val developerModeDetector by lazy { DeveloperModeDetector(context) }
  private val networkMonitor by lazy { NetworkMonitor(context) }
  private val overlayDetector by lazy { OverlayDetector(context) }
  private val screenMonitor by lazy { ScreenMonitor(context) }
  private val integrityChecker by lazy { IntegrityChecker(context) }

  @Volatile
  private var eventListener: ((NativeSecurityEvent) -> Unit)? = null

  private val monitor by lazy {
    SecurityMonitor(
      context = context,
      rootDetector = rootDetector,
      hookDetector = hookDetector,
      integrityChecker = integrityChecker,
      networkMonitor = networkMonitor,
      screenMonitor = screenMonitor,
      developerModeDetector = developerModeDetector
    ) { event ->
      eventListener?.invoke(NativeSecurityEvent(event.type, event.message, event.timestamp))
    }
  }

  override fun isRooted(): Promise<Boolean> = Promise.parallel { rootDetector.isRooted() }

  override fun isMagiskDetected(): Promise<Boolean> =
    Promise.parallel { magiskDetector.isDetected() }

  override fun isBusyBoxDetected(): Promise<Boolean> =
    Promise.parallel { busyBoxDetector.isDetected() }

  /** Jailbreak is an iOS-only concept; always `false` on Android. */
  override fun isJailbroken(): Promise<Boolean> = Promise.resolved(false)

  override fun isEmulator(): Promise<Boolean> = Promise.parallel { emulatorDetector.isDetected() }

  override fun isDeveloperModeEnabled(): Promise<Boolean> =
    Promise.parallel { developerModeDetector.isDeveloperModeEnabled() }

  override fun isUsbDebuggingEnabled(): Promise<Boolean> =
    Promise.parallel { developerModeDetector.isUsbDebuggingEnabled() }

  override fun isDebuggerAttached(): Promise<Boolean> =
    Promise.parallel { developerModeDetector.isDebuggerAttached() }

  override fun isMockLocationEnabled(): Promise<Boolean> =
    Promise.parallel { developerModeDetector.isMockLocationEnabled() }

  override fun isVpnConnected(): Promise<Boolean> =
    Promise.parallel { networkMonitor.isVpnConnected() }

  override fun isProxyEnabled(): Promise<Boolean> =
    Promise.parallel { networkMonitor.isProxyEnabled() }

  override fun isScreenRecording(): Promise<Boolean> =
    Promise.parallel { screenMonitor.isScreenRecording() }

  override fun isScreenCaptured(): Promise<Boolean> =
    Promise.parallel { screenMonitor.isScreenCaptured() }

  override fun hasOverlayPermission(): Promise<Boolean> =
    Promise.parallel { overlayDetector.hasOverlayPermission() }

  override fun isHookDetected(): Promise<Boolean> =
    Promise.parallel { hookDetector.isAnyHookDetected() }

  override fun isFridaDetected(): Promise<Boolean> =
    Promise.parallel { hookDetector.isFridaDetected() }

  override fun isXposedDetected(): Promise<Boolean> =
    Promise.parallel { hookDetector.isXposedDetected() }

  override fun isLSPosedDetected(): Promise<Boolean> =
    Promise.parallel { hookDetector.isLSPosedDetected() }

  override fun isTampered(): Promise<Boolean> = Promise.parallel { integrityChecker.isTampered() }

  override fun getAppSignatureHash(): Promise<String> =
    Promise.parallel { integrityChecker.getAppSignatureHash() }

  override fun verifyAppSignature(expectedSignatureHash: String): Promise<Boolean> =
    Promise.parallel { integrityChecker.verifyAppSignature(expectedSignatureHash) }

  override fun verifyApkIntegrity(expectedSha256: String): Promise<Boolean> =
    Promise.parallel { integrityChecker.verifyApkIntegrity(expectedSha256) }

  /** Android's TLS stack (OkHttp/`URLConnection`) always supports pinning; this is informational. */
  override fun isSslPinningSupported(): Promise<Boolean> = Promise.resolved(true)

  override fun scan(): Promise<NativeScanResult> = Promise.parallel {
    val reasons = mutableListOf<String>()

    val rootReasons = rootDetector.reasons()
    reasons += rootReasons
    val isRootedValue = rootReasons.isNotEmpty()

    val isMagisk = magiskDetector.isDetected()
    if (isMagisk) reasons += "Magisk detected"

    val isBusyBox = busyBoxDetector.isDetected()
    if (isBusyBox) reasons += "BusyBox binary detected"

    val isEmu = emulatorDetector.isDetected()
    if (isEmu) reasons += "Running on an emulator"

    val isFrida = hookDetector.isFridaDetected()
    if (isFrida) reasons += "Frida detected"

    val isXposed = hookDetector.isXposedDetected()
    if (isXposed) reasons += "Xposed/EdXposed detected"

    val isLSPosed = hookDetector.isLSPosedDetected()
    if (isLSPosed) reasons += "LSPosed detected"

    val isSubstrateOrRiru = hookDetector.isSubstrateOrRiruDetected()
    if (isSubstrateOrRiru) reasons += "Substrate/Riru injection layer detected"

    val hookAny = isFrida || isXposed || isLSPosed || isSubstrateOrRiru

    val devMode = developerModeDetector.isDeveloperModeEnabled()
    if (devMode) reasons += "Developer mode enabled"

    val usbDebug = developerModeDetector.isUsbDebuggingEnabled()
    if (usbDebug) reasons += "USB debugging enabled"

    val debuggerAttached = developerModeDetector.isDebuggerAttached()
    if (debuggerAttached) reasons += "Debugger attached to process"

    val mockLoc = developerModeDetector.isMockLocationEnabled()
    if (mockLoc) reasons += "Mock location provider enabled"

    val vpn = networkMonitor.isVpnConnected()
    if (vpn) reasons += "VPN connection active"

    val proxy = networkMonitor.isProxyEnabled()
    if (proxy) reasons += "System proxy configured"

    val overlay = overlayDetector.hasOverlayPermission()
    if (overlay) reasons += "Overlay draw permission/app detected"

    val screenRec = screenMonitor.isScreenRecording()
    if (screenRec) reasons += "Screen recording/mirroring signal detected"

    val screenCap = screenMonitor.isScreenCaptured()

    val tampered = integrityChecker.isTampered()
    if (tampered) reasons += "App tamper signal detected"

    val checks = NativeSecurityChecks(
      root = isRootedValue,
      jailbreak = false,
      emulator = isEmu,
      developerMode = devMode,
      usbDebugging = usbDebug,
      vpn = vpn,
      proxy = proxy,
      overlay = overlay,
      frida = isFrida,
      xposed = isXposed,
      lsposed = isLSPosed,
      magisk = isMagisk,
      busybox = isBusyBox,
      mockLocation = mockLoc,
      hookDetected = hookAny,
      tampered = tampered,
      // No app-supplied "known good" hash is available in a zero-config scan();
      // call verifyAppSignature() directly for an authoritative check.
      signatureValid = true,
      sslPinningSupported = true,
      screenRecording = screenRec,
      screenCaptured = screenCap,
      debuggerAttached = debuggerAttached
    )

    NativeScanResult(checks = checks, reasons = reasons.toTypedArray())
  }

  override fun setEventListener(listener: (event: NativeSecurityEvent) -> Unit) {
    eventListener = listener
  }

  override fun removeEventListener() {
    eventListener = null
  }

  override fun startMonitoring() {
    monitor.start()
  }

  override fun stopMonitoring() {
    monitor.stop()
  }
}