package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.util.ShellUtils
import java.io.File
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Detects the most common Android instrumentation/hooking frameworks:
 * Frida, Xposed, LSPosed, EdXposed, Cydia Substrate and Riru (the Zygote
 * injection layer several of the above build on).
 */
internal class HookDetector(private val context: Context) {

  // --- Frida -----------------------------------------------------------------

  private val fridaDefaultPorts = intArrayOf(27042, 27043)

  fun checkFrida(): NativeDetectionResult = Detection.run {
    signal("FRIDA_IN_MEMORY_MAPS", NativeConfidence.HIGH) {
      val maps = ShellUtils.readFile("/proc/self/maps")
      listOf("frida-agent", "frida-gadget", "gum-js-loop", "linjector").any { maps.contains(it) }
    }
    signal("FRIDA_THREAD", NativeConfidence.HIGH) { hasThreadNamed("gum-js-loop", "frida") }
    // GLib threads that frida-agent spawns; rarely present in a normal Android app.
    signal("FRIDA_GLIB_THREAD", NativeConfidence.MEDIUM) { hasThreadNamed("gmain", "gdbus") }
    // Something listening on Frida's default ports — frida-server may also use custom ports.
    signal("FRIDA_PORT_OPEN", NativeConfidence.MEDIUM) { fridaDefaultPorts.any { isLoopbackPortOpen(it) } }
  }

  private fun isLoopbackPortOpen(port: Int): Boolean {
    return try {
      Socket().use { socket ->
        socket.connect(InetSocketAddress("127.0.0.1", port), 200)
        true
      }
    } catch (_: ConnectException) {
      false
    } catch (_: SocketTimeoutException) {
      false
    }
  }

  private fun hasThreadNamed(vararg markers: String): Boolean {
    val threadDirs = File("/proc/self/task").listFiles()
      ?: throw IllegalStateException("/proc/self/task unreadable")
    return threadDirs.any { dir ->
      val comm = ShellUtils.readFileOrNull(File(dir, "comm").path)?.trim()
      comm != null && markers.any { comm.contains(it) }
    }
  }

  // --- Xposed / EdXposed --------------------------------------------------------

  fun checkXposed(): NativeDetectionResult = Detection.run {
    signal("XPOSED_BRIDGE_CLASS", NativeConfidence.HIGH) {
      isClassPresent("de.robv.android.xposed.XposedBridge") ||
        isClassPresent("de.robv.android.xposed.XC_MethodHook")
    }
    signal("XPOSED_FRAMEWORK_FILE", NativeConfidence.HIGH) {
      File("/system/framework/XposedBridge.jar").exists()
    }
    signal("XPOSED_MANAGER_APP", NativeConfidence.MEDIUM) {
      KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.XPOSED)
    }
  }

  // --- LSPosed -----------------------------------------------------------------

  // SELinux blocks untrusted apps from /data/adb and /data/misc, so these
  // paths only fire on permissive/misconfigured devices.
  private val lsposedPaths = arrayOf(
    "/data/adb/lspd",
    "/data/misc/lspd",
    "/data/adb/modules/zygisk_lsposed"
  )

  fun checkLSPosed(): NativeDetectionResult = Detection.run {
    signal("LSPOSED_CLASS", NativeConfidence.HIGH) { isClassPresent("org.lsposed.lspd.core.Main") }
    signal("LSPOSED_MANAGER_APP", NativeConfidence.MEDIUM) {
      KnownPackages.isAnyInstalled(context.packageManager, KnownPackages.LSPOSED)
    }
    signal("LSPOSED_FILES", NativeConfidence.HIGH) { lsposedPaths.any { File(it).exists() } }
  }

  // --- Substrate / Riru ------------------------------------------------------------

  // Same SELinux caveat as lsposedPaths.
  private val riruPaths = arrayOf(
    "/data/misc/riru",
    "/data/adb/riru",
    "/data/adb/modules/riru-core"
  )

  fun checkSubstrateOrRiru(): NativeDetectionResult = Detection.run {
    signal("SUBSTRATE_APP", NativeConfidence.MEDIUM) {
      KnownPackages.isInstalled(context.packageManager, KnownPackages.SUBSTRATE)
    }
    signal("SUBSTRATE_FILES", NativeConfidence.HIGH) { File("/data/data/com.saurik.substrate").exists() }
    signal("RIRU_FILES", NativeConfidence.HIGH) { riruPaths.any { File(it).exists() } }
    signal("SUBSTRATE_IN_MEMORY_MAPS", NativeConfidence.HIGH) {
      ShellUtils.readFile("/proc/self/maps").contains("libsubstrate")
    }
  }

  /** Umbrella result combining every hooking-framework detector. */
  fun checkHooks(): NativeDetectionResult = Detection.run {
    include(checkFrida())
    include(checkXposed())
    include(checkLSPosed())
    include(checkSubstrateOrRiru())
  }

  private fun isClassPresent(className: String): Boolean {
    return try {
      Class.forName(className)
      true
    } catch (_: ClassNotFoundException) {
      false
    }
  }
}
