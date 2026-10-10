package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import java.net.NetworkInterface
import java.util.Collections

internal class NetworkMonitor(private val context: Context) {

  private val connectivityManager: ConnectivityManager
    get() = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
      ?: throw IllegalStateException("ConnectivityManager unavailable")

  fun checkVpn(): NativeDetectionResult = Detection.run {
    signal("VPN_TRANSPORT", NativeConfidence.HIGH) {
      val cm = connectivityManager
      // No active network at all (airplane mode) simply means no VPN.
      val network = cm.activeNetwork ?: return@signal false
      cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }
    // Cross-check: a tunnel interface that's up even if it isn't the active network.
    signal("VPN_INTERFACE", NativeConfidence.MEDIUM) {
      Collections.list(NetworkInterface.getNetworkInterfaces()).any { iface ->
        iface.isUp && (iface.name.startsWith("tun") || iface.name.startsWith("ppp") || iface.name.startsWith("pptp"))
      }
    }
  }

  fun checkProxy(): NativeDetectionResult = Detection.run {
    signal("SYSTEM_PROXY_PROPERTY", NativeConfidence.HIGH) {
      !System.getProperty("http.proxyHost").isNullOrEmpty() &&
        !System.getProperty("http.proxyPort").isNullOrEmpty()
    }
    signal("NETWORK_PROXY", NativeConfidence.HIGH) {
      !connectivityManager.defaultProxy?.host.isNullOrEmpty()
    }
  }

  fun isProxyEnabled(): Boolean = checkProxy().isDetected
}
