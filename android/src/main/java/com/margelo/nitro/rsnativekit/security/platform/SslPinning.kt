package com.margelo.nitro.rsnativekit.security.platform

import android.content.Context
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import com.margelo.nitro.rsnativekit.security.NativePinnedDomain
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

/**
 * Enforces public-key pinning on React Native's networking stack: installs an
 * [OkHttpClientFactory] whose clients carry a [CertificatePinner], so every
 * `fetch`/`XMLHttpRequest` to a pinned host fails unless the server's chain
 * contains a pinned key. RN's networking module builds its client once, so
 * this must run before the first request. WebSockets and image loading use
 * their own clients and aren't covered.
 */
internal object SslPinning {

  @Volatile
  private var enabled = false

  @Synchronized
  fun enable(context: Context, domains: Array<NativePinnedDomain>) {
    check(!enabled) { "SSL pinning is already enabled; it can only be configured once per app launch" }
    require(domains.isNotEmpty()) { "at least one pinned domain is required" }

    val pinner = CertificatePinner.Builder().apply {
      for (domain in domains) {
        require(domain.pins.size >= 2) { "${domain.hostname} needs at least two pins (one backup)" }
        val pins = domain.pins.map { "sha256/$it" }.toTypedArray()
        add(domain.hostname, *pins)
        // OkHttp's `**.` matches the domain itself and any depth of subdomain.
        if (domain.includeSubdomains) add("**.${domain.hostname}", *pins)
      }
    }.build()

    val appContext = context.applicationContext
    OkHttpClientProvider.setOkHttpClientFactory(object : OkHttpClientFactory {
      override fun createNewNetworkModuleClient(): OkHttpClient =
        OkHttpClientProvider.createClientBuilder(appContext).certificatePinner(pinner).build()
    })
    enabled = true
  }
}
