package com.margelo.nitro.rsnativekit.security.attestation

import android.content.Context
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Play Integrity API, Standard requests: `prepare()` warms up a token
 * provider once (a few seconds); `request()` then returns a token bound to
 * the request in milliseconds. The token is opaque to the app — only your
 * server can decode and verify it (see the `server/` verifier package), so
 * nothing here makes a trust decision on the device.
 */
internal class PlayIntegrity(private val context: Context) {

  companion object {
    private const val PREPARE_TIMEOUT_SECONDS = 30L
    private const val REQUEST_TIMEOUT_SECONDS = 30L
  }

  private val lock = Any()
  private var provider: StandardIntegrityTokenProvider? = null
  private var cloudProjectNumber: Long? = null

  fun prepare(cloudProjectNumber: Long) {
    require(cloudProjectNumber > 0) { "cloudProjectNumber must be a positive Google Cloud project number" }
    val manager = IntegrityManagerFactory.createStandard(context)
    val prepared = Tasks.await(
      manager.prepareIntegrityToken(
        PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build()
      ),
      PREPARE_TIMEOUT_SECONDS,
      TimeUnit.SECONDS
    )
    synchronized(lock) {
      provider = prepared
      this.cloudProjectNumber = cloudProjectNumber
    }
  }

  /** Token whose `requestHash` is the hex SHA-256 of [requestData]. */
  fun request(requestData: String): String {
    val requestHash = sha256Hex(requestData)
    return try {
      requestWith(currentProvider(), requestHash)
    } catch (e: Exception) {
      // Providers expire; Google's guidance is to prepare a new one and retry once.
      if (!isProviderInvalid(e)) throw e
      val projectNumber = synchronized(lock) { cloudProjectNumber }
        ?: throw IllegalStateException("Call prepareIntegrityToken() before requestIntegrityToken()")
      prepare(projectNumber)
      requestWith(currentProvider(), requestHash)
    }
  }

  private fun currentProvider(): StandardIntegrityTokenProvider =
    synchronized(lock) { provider }
      ?: throw IllegalStateException("Call prepareIntegrityToken() before requestIntegrityToken()")

  private fun requestWith(provider: StandardIntegrityTokenProvider, requestHash: String): String {
    val response = Tasks.await(
      provider.request(StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()),
      REQUEST_TIMEOUT_SECONDS,
      TimeUnit.SECONDS
    )
    return response.token()
  }

  private fun isProviderInvalid(e: Exception): Boolean {
    val cause = (e.cause as? StandardIntegrityException) ?: (e as? StandardIntegrityException) ?: return false
    return cause.errorCode == StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID
  }

  private fun sha256Hex(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
      .joinToString("") { "%02x".format(it) }
}
