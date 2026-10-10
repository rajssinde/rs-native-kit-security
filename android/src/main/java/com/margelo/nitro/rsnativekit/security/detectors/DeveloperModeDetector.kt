package com.margelo.nitro.rsnativekit.security.detectors

import android.app.AppOpsManager
import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.Process
import android.provider.Settings

internal class DeveloperModeDetector(private val context: Context) {

  fun isDeveloperModeEnabled(): Boolean {
    return try {
      Settings.Global.getInt(
        context.contentResolver,
        Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
        0
      ) != 0
    } catch (_: Exception) {
      false
    }
  }

  fun isUsbDebuggingEnabled(): Boolean {
    return try {
      Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
    } catch (_: Exception) {
      false
    }
  }

  /** Native debugger (JDWP/ptrace) attach detection — independent of any RN/JS debugger. */
  fun isDebuggerAttached(): Boolean {
    return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
  }

  fun isMockLocationEnabled(): Boolean {
    return isMockLocationAppOpEnabled() || isLegacyMockLocationSettingEnabled() || hasMockLocationApp()
  }

  /** API 23+: `AppOpsManager` tracks whether this app was granted the mock-location app-op. */
  @Suppress("DEPRECATION")
  private fun isMockLocationAppOpEnabled(): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
    return try {
      val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
        ?: return false
      val mode = appOps.checkOpNoThrow(
        AppOpsManager.OPSTR_MOCK_LOCATION,
        Process.myUid(),
        context.packageName
      )
      mode == AppOpsManager.MODE_ALLOWED
    } catch (_: Exception) {
      false
    }
  }

  /** Pre-API-23 fallback: the (now-removed) `Settings.Secure.ALLOW_MOCK_LOCATION` flag. */
  @Suppress("DEPRECATION")
  private fun isLegacyMockLocationSettingEnabled(): Boolean {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) return false
    return try {
      Settings.Secure.getString(context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION) != "0"
    } catch (_: Exception) {
      false
    }
  }

  private fun hasMockLocationApp(): Boolean {
    return KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.MOCK_LOCATION_APPS)
  }
}