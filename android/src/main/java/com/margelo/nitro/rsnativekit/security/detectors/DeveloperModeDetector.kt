package com.margelo.nitro.rsnativekit.security.detectors

import android.app.AppOpsManager
import android.content.Context
import android.os.Debug
import android.os.Process
import android.provider.Settings
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult

internal class DeveloperModeDetector(private val context: Context) {

  fun checkDeveloperMode(): NativeDetectionResult = Detection.run {
    signal("DEVELOPER_OPTIONS_ENABLED", NativeConfidence.HIGH) {
      Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
    }
  }

  fun checkUsbDebugging(): NativeDetectionResult = Detection.run {
    signal("ADB_ENABLED", NativeConfidence.HIGH) {
      Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
    }
  }

  /** Java (JDWP) debugger attach detection — independent of any RN/JS debugger. */
  fun checkDebugger(): NativeDetectionResult = Detection.run {
    signal("JDWP_DEBUGGER_ATTACHED", NativeConfidence.HIGH) {
      Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }
  }

  fun isDebuggerAttached(): Boolean = Debug.isDebuggerConnected() || Debug.waitingForDebugger()

  fun checkMockLocation(): NativeDetectionResult = Detection.run {
    // True when *this* app has been selected as the mock-location provider.
    signal("MOCK_LOCATION_APPOP", NativeConfidence.HIGH) {
      val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
        ?: throw IllegalStateException("AppOpsManager unavailable")
      @Suppress("DEPRECATION")
      appOps.checkOpNoThrow(AppOpsManager.OPSTR_MOCK_LOCATION, Process.myUid(), context.packageName) ==
        AppOpsManager.MODE_ALLOWED
    }
    // An installed fake-GPS app is only a weak hint: it may not be the active provider.
    signal("MOCK_LOCATION_APP_INSTALLED", NativeConfidence.LOW) {
      KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.MOCK_LOCATION_APPS)
    }
  }
}
