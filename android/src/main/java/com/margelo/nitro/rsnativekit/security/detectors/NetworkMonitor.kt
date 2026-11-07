package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
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
    // JVM-wide proxies, set by the app, an SDK, or a hook that wants traffic routed elsewhere.
    signal("SYSTEM_PROXY_PROPERTY", NativeConfidence.HIGH) {
      JVM_PROXY_HOST_PROPERTIES.any { !System.getProperty(it).isNullOrEmpty() }
    }
    signal("NETWORK_PROXY", NativeConfidence.HIGH) {
      !connectivityManager.defaultProxy?.host.isNullOrEmpty()
    }
    // Proxy auto-config (PAC) can route traffic through a proxy just as well.
    signal("PAC_PROXY", NativeConfidence.MEDIUM) {
      val pac = connectivityManager.defaultProxy?.pacFileUrl
      pac != null && pac != Uri.EMPTY && pac.toString().isNotEmpty()
    }
  }

  fun isProxyEnabled(): Boolean = checkProxy().isDetected
}

private val JVM_PROXY_HOST_PROPERTIES = listOf("http.proxyHost", "https.proxyHost", "socksProxyHost")
