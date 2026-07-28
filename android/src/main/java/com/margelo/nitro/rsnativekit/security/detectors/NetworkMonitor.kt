package com.margelo.nitro.rsnativekit.security.detectors

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.net.NetworkInterface
import java.util.Collections

internal class NetworkMonitor(private val context: Context) {

  fun isVpnConnected(): Boolean {
    return isVpnActiveViaConnectivityManager() || hasVpnNetworkInterface()
  }

  private fun isVpnActiveViaConnectivityManager(): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
    return try {
      val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        ?: return false
      val network = cm.activeNetwork ?: return false
      val capabilities = cm.getNetworkCapabilities(network) ?: return false
      capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    } catch (_: Exception) {
      false
    }
  }

  /** Fallback for pre-M devices (and a cross-check on newer ones): scan for tunnel interfaces. */
  private fun hasVpnNetworkInterface(): Boolean {
    return try {
      Collections.list(NetworkInterface.getNetworkInterfaces()).any { iface ->
        iface.isUp && (iface.name.startsWith("tun") || iface.name.startsWith("ppp") || iface.name.startsWith("pptp"))
      }
    } catch (_: Exception) {
      false
    }
  }

  fun isProxyEnabled(): Boolean {
    return hasSystemProxyProperty() || hasConnectivityManagerProxy()
  }

  private fun hasSystemProxyProperty(): Boolean {
    val host = System.getProperty("http.proxyHost")
    val port = System.getProperty("http.proxyPort")
    return !host.isNullOrEmpty() && !port.isNullOrEmpty()
  }

  private fun hasConnectivityManagerProxy(): Boolean {
    return try {
      val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        ?: return false
      val proxyInfo = cm.defaultProxy
      proxyInfo != null && !proxyInfo.host.isNullOrEmpty()
    } catch (_: Exception) {
      false
    }
  }
}