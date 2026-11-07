package com.margelo.nitro.rsnativekit.security.attestation

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Android Key Attestation: generates a throwaway EC key in the TEE (or
 * StrongBox) with the server's challenge baked into its attestation, and
 * returns the certificate chain. The chain's leaf carries the bootloader-lock
 * and verified-boot state signed by the secure hardware, which root-hiding
 * tools running in Android can't alter. Like Play Integrity, nothing here
 * makes a trust decision — the `server/` verifier does.
 */
internal class KeyAttestation {

  companion object {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS_PREFIX = "rs_native_kit_key_attestation_"
  }

  /** Base64 DER certificates, leaf first. */
  fun attest(challenge: String): Array<String> {
    val challengeBytes = challenge.toByteArray(Charsets.UTF_8)
    require(challengeBytes.size in 1..128) { "challenge must be 1-128 bytes in UTF-8" }

    val alias = ALIAS_PREFIX + UUID.randomUUID()
    val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
    try {
      val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAttestationChallenge(challengeBytes)
        .build()
      KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).run {
        initialize(spec)
        generateKeyPair()
      }
      val chain = keyStore.getCertificateChain(alias)
      check(!chain.isNullOrEmpty()) { "Keystore returned no attestation certificate chain" }
      return Array(chain.size) { Base64.encodeToString(chain[it].encoded, Base64.NO_WRAP) }
    } finally {
      // The key exists only to carry the attestation; never leave it behind.
      keyStore.deleteEntry(alias)
    }
  }
}
