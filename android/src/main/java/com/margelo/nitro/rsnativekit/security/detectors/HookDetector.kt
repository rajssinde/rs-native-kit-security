package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import com.margelo.nitro.rsnativekit.security.util.ShellUtils
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Detects the most common Android instrumentation/hooking frameworks:
 * Frida, Xposed, LSPosed, EdXposed, Cydia Substrate and Riru (the Zygote
 * injection layer several of the above build on).
 */
internal class HookDetector(private val context: Context) {

  // --- Frida -----------------------------------------------------------------

  private val fridaDefaultPorts = intArrayOf(27042, 27043)

  fun isFridaDetected(): Boolean {
    return hasFridaPortOpen() || hasFridaArtifactsInMaps() || hasFridaThreads()
  }

  private fun hasFridaPortOpen(): Boolean {
    return fridaDefaultPorts.any { port ->
      try {
        Socket().use { socket ->
          socket.connect(InetSocketAddress("127.0.0.1", port), 200)
          true
        }
      } catch (_: Exception) {
        false
      }
    }
  }

  private fun hasFridaArtifactsInMaps(): Boolean {
    val maps = ShellUtils.readFileOrNull("/proc/self/maps") ?: return false
    val markers = listOf("frida-agent", "frida-gadget", "gum-js-loop", "linjector")
    return markers.any { maps.contains(it) }
  }

  private fun hasFridaThreads(): Boolean {
    val tasksDir = File("/proc/self/task")
    val threadDirs = tasksDir.listFiles() ?: return false
    val markers = listOf("gum-js-loop", "gmain", "gdbus", "frida")
    return threadDirs.any { dir ->
      val comm = ShellUtils.readFileOrNull(File(dir, "comm").path)?.trim()
      comm != null && markers.any { comm.contains(it) }
    }
  }

  // --- Xposed / EdXposed --------------------------------------------------------

  fun isXposedDetected(): Boolean {
    return isClassPresent("de.robv.android.xposed.XposedBridge") ||
      isClassPresent("de.robv.android.xposed.XC_MethodHook") ||
      File("/system/framework/XposedBridge.jar").exists() ||
      isAnyPackageInstalled(KnownPackages.XPOSED)
  }

  // --- LSPosed -----------------------------------------------------------------

  // SELinux blocks untrusted apps from /data/adb and /data/misc, so these
  // paths only fire on permissive/misconfigured devices.
  private val lsposedPaths = arrayOf(
    "/data/adb/lspd",
    "/data/misc/lspd",
    "/data/adb/modules/zygisk_lsposed"
  )

  fun isLSPosedDetected(): Boolean {
    return isClassPresent("org.lsposed.lspd.core.Main") ||
      isAnyPackageInstalled(KnownPackages.LSPOSED) ||
      lsposedPaths.any { File(it).exists() }
  }

  // --- Substrate / Riru ------------------------------------------------------------

  // Same SELinux caveat as lsposedPaths.
  private val riruPaths = arrayOf(
    "/data/misc/riru",
    "/data/adb/riru",
    "/data/adb/modules/riru-core"
  )

  fun isSubstrateOrRiruDetected(): Boolean {
    return KnownPackages.isInstalled(context.packageManager, KnownPackages.SUBSTRATE) ||
      File("/data/data/com.saurik.substrate").exists() ||
      riruPaths.any { File(it).exists() } ||
      hasSubstrateArtifactsInMaps()
  }

  private fun hasSubstrateArtifactsInMaps(): Boolean {
    val maps = ShellUtils.readFileOrNull("/proc/self/maps") ?: return false
    return maps.contains("libsubstrate") || maps.contains("libsubstrate-dvm")
  }

  /** Umbrella check combining every hooking-framework signal. */
  fun isAnyHookDetected(): Boolean {
    return isFridaDetected() ||
      isXposedDetected() ||
      isLSPosedDetected() ||
      isSubstrateOrRiruDetected()
  }

  private fun isClassPresent(className: String): Boolean {
    return try {
      Class.forName(className)
      true
    } catch (_: ClassNotFoundException) {
      false
    } catch (_: Exception) {
      false
    }
  }

  private fun isAnyPackageInstalled(packages: Array<String>): Boolean {
    return KnownPackages.isAnyInstalled(context.packageManager, packages)
  }
}