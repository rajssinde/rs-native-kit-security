package com.margelo.nitro.rsnativekit.security

import android.os.SystemClock
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.Promise
import com.margelo.nitro.rsnativekit.security.attestation.PlayIntegrity
import com.margelo.nitro.rsnativekit.security.detectors.BusyBoxDetector
import com.margelo.nitro.rsnativekit.security.detectors.Detection
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
 *
 * Every check goes through [guarded], so an unexpected exception in a
 * detector becomes an `error` result instead of a rejected promise or, worse,
 * a silent "not detected".
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
  private val playIntegrity by lazy { PlayIntegrity(context) }

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

  private inline fun guarded(check: () -> NativeDetectionResult): NativeDetectionResult {
    return try {
      check()
    } catch (e: Throwable) {
      Detection.failed(e)
    }
  }

  private fun async(check: () -> NativeDetectionResult): Promise<NativeDetectionResult> =
    Promise.parallel { guarded(check) }

  override fun checkRoot() = async { rootDetector.check() }
  override fun checkMagisk() = async { magiskDetector.check() }
  override fun checkBusyBox() = async { busyBoxDetector.check() }

  /** Jailbreak is an iOS-only concept. */
  override fun checkJailbreak(): Promise<NativeDetectionResult> = Promise.resolved(Detection.unsupported())

  override fun checkEmulator() = async { emulatorDetector.check() }
  override fun checkDeveloperMode() = async { developerModeDetector.checkDeveloperMode() }
  override fun checkUsbDebugging() = async { developerModeDetector.checkUsbDebugging() }
  override fun checkDebugger() = async { developerModeDetector.checkDebugger() }
  override fun checkMockLocation() = async { developerModeDetector.checkMockLocation() }
  override fun checkVpn() = async { networkMonitor.checkVpn() }
  override fun checkProxy() = async { networkMonitor.checkProxy() }
  override fun checkScreenRecording() = async { screenMonitor.checkScreenRecording() }
  override fun checkScreenCapture() = async { screenMonitor.checkScreenCapture() }
  override fun checkOverlay() = async { overlayDetector.check() }
  override fun checkHooks() = async { hookDetector.checkHooks() }
  override fun checkFrida() = async { hookDetector.checkFrida() }
  override fun checkXposed() = async { hookDetector.checkXposed() }
  override fun checkLSPosed() = async { hookDetector.checkLSPosed() }
  override fun checkTampering() = async { integrityChecker.checkTampering() }

  override fun checkSignature(expectedSigners: Array<String>) =
    async { integrityChecker.checkSignature(expectedSigners) }

  override fun checkApkIntegrity(expectedSha256: String) =
    async { integrityChecker.checkApkIntegrity(expectedSha256) }

  override fun getSigningIdentity(): Promise<String> =
    Promise.parallel { integrityChecker.getAppSignatureHash() }

  override fun prepareIntegrityToken(cloudProjectNumber: Double): Promise<Unit> = Promise.parallel {
    playIntegrity.prepare(cloudProjectNumber.toLong())
  }

  override fun requestIntegrityToken(requestData: String): Promise<String> =
    Promise.parallel { playIntegrity.request(requestData) }

  /** App Attest is iOS-only; Android apps use Play Integrity instead. */
  override fun isAppAttestSupported(): Promise<Boolean> = Promise.resolved(false)

  override fun generateAppAttestKey(): Promise<String> = Promise.rejected(appAttestUnavailable())

  override fun attestAppAttestKey(keyId: String, challenge: String): Promise<String> =
    Promise.rejected(appAttestUnavailable())

  override fun generateAppAttestAssertion(keyId: String, clientData: String): Promise<String> =
    Promise.rejected(appAttestUnavailable())

  private fun appAttestUnavailable() =
    UnsupportedOperationException("App Attest is iOS-only; use Play Integrity on Android")

  override fun scan(options: NativeScanOptions): Promise<NativeScanResult> = Promise.parallel {
    val startedAt = SystemClock.elapsedRealtime()

    val frida = guarded { hookDetector.checkFrida() }
    val xposed = guarded { hookDetector.checkXposed() }
    val lsposed = guarded { hookDetector.checkLSPosed() }
    // Reuse the individual hook results instead of running every probe twice.
    val hooks = guarded {
      Detection.run {
        include(frida)
        include(xposed)
        include(lsposed)
        include(hookDetector.checkSubstrateOrRiru())
      }
    }

    val checks = NativeSecurityChecks(
      root = guarded { rootDetector.check() },
      magisk = guarded { magiskDetector.check() },
      busybox = guarded { busyBoxDetector.check() },
      jailbreak = Detection.unsupported(),
      emulator = guarded { emulatorDetector.check() },
      developerMode = guarded { developerModeDetector.checkDeveloperMode() },
      usbDebugging = guarded { developerModeDetector.checkUsbDebugging() },
      debugger = guarded { developerModeDetector.checkDebugger() },
      mockLocation = guarded { developerModeDetector.checkMockLocation() },
      vpn = guarded { networkMonitor.checkVpn() },
      proxy = guarded { networkMonitor.checkProxy() },
      screenRecording = guarded { screenMonitor.checkScreenRecording() },
      screenCapture = guarded { screenMonitor.checkScreenCapture() },
      overlay = guarded { overlayDetector.check() },
      hooks = hooks,
      frida = frida,
      xposed = xposed,
      lsposed = lsposed,
      tampering = guarded { integrityChecker.checkTampering() },
      signature = guarded { integrityChecker.checkSignature(options.expectedSigners) }
    )

    NativeScanResult(checks = checks, durationMs = (SystemClock.elapsedRealtime() - startedAt).toDouble())
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
