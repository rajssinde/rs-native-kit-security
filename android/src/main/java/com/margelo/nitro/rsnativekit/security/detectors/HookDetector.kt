package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.util.NativeChecks
import com.margelo.nitro.rsnativekit.security.util.ShellUtils
import android.system.ErrnoException
import android.system.Os
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
      val maps = ShellUtils.readProcFile("/proc/self/maps")
      listOf("frida-agent", "frida-gadget", "gum-js-loop", "linjector").any { maps.contains(it) }
    }
    signal("FRIDA_THREAD", NativeConfidence.HIGH) { hasThreadNamed("gum-js-loop", "frida") }
    // GLib threads that frida-agent spawns; rarely present in a normal Android app.
    signal("FRIDA_GLIB_THREAD", NativeConfidence.MEDIUM) { hasThreadNamed("gmain", "gdbus") }
    // Pipes/sockets frida's injector and agent hold open in the target process.
    signal("FRIDA_FILE_DESCRIPTOR", NativeConfidence.HIGH) { hasFileDescriptorMatching("linjector", "frida") }
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

  private fun hasFileDescriptorMatching(vararg markers: String): Boolean {
    val descriptors = File("/proc/self/fd").listFiles()
      ?: throw IllegalStateException("/proc/self/fd unreadable")
    return descriptors.any { fd ->
      val target = try {
        Os.readlink(fd.path)
      } catch (_: ErrnoException) {
        return@any false // closed between listing and reading
      }
      markers.any { target.contains(it) }
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
      ShellUtils.readProcFile("/proc/self/maps").contains("libsubstrate")
    }
  }

  // --- Hooked file APIs ---------------------------------------------------------

  /** Root/instrumentation artefacts hiding tools try to make invisible to Java. */
  private val hiddenArtefactPaths = ShellUtils.COMMON_BIN_PATHS.map { "${it}su" } + listOf(
    "/sbin/.magisk",
    "/system/bin/magisk",
    "/debug_ramdisk/magisk",
    "/system/framework/XposedBridge.jar"
  )

  /**
   * A path the raw-syscall probe sees but `java.io.File` doesn't can only mean
   * the Java file API is hooked to hide it — itself proof of instrumentation.
   */
  fun checkFileApiHooks(): NativeDetectionResult = Detection.run {
    signal("FILE_API_HOOKED", NativeConfidence.HIGH) {
      hiddenArtefactPaths.any { NativeChecks.exists(it) && !File(it).exists() }
    }
  }

  /** Umbrella result combining every hooking-framework detector. */
  fun checkHooks(): NativeDetectionResult = Detection.run {
    include(checkFrida())
    include(checkXposed())
    include(checkLSPosed())
    include(checkSubstrateOrRiru())
    include(checkFileApiHooks())
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
