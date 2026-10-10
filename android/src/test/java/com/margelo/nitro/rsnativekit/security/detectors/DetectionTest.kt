package com.margelo.nitro.rsnativekit.security.detectors

import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DetectionTest {

  private fun fail(): Boolean = throw IllegalStateException("probe failed")

  @Test
  fun `a fired signal makes the result detected with that signal's confidence`() {
    val result = Detection.run {
      signal("WEAK", NativeConfidence.LOW) { true }
      signal("STRONG", NativeConfidence.HIGH) { true }
      signal("QUIET", NativeConfidence.HIGH) { false }
    }
    assertEquals(NativeDetectionStatus.DETECTED, result.status)
    assertArrayEquals(arrayOf("WEAK", "STRONG"), result.reasons)
    assertEquals(NativeConfidence.HIGH, result.confidence)
  }

  @Test
  fun `no fired signals is not_detected with medium confidence, never high`() {
    val result = Detection.run { signal("A", NativeConfidence.HIGH) { false } }
    assertEquals(NativeDetectionStatus.NOT_DETECTED, result.status)
    assertEquals(NativeConfidence.MEDIUM, result.confidence)
    assertNull(result.error)
  }

  @Test
  fun `a failed probe lowers confidence instead of reading as clean`() {
    val result = Detection.run {
      signal("A", NativeConfidence.HIGH) { false }
      signal("B", NativeConfidence.HIGH) { fail() }
    }
    assertEquals(NativeDetectionStatus.NOT_DETECTED, result.status)
    assertEquals(NativeConfidence.LOW, result.confidence)
    assertEquals("B: probe failed", result.error)
  }

  @Test
  fun `every probe failing is an error, not not_detected`() {
    val result = Detection.run { signal("A", NativeConfidence.HIGH) { fail() } }
    assertEquals(NativeDetectionStatus.ERROR, result.status)
    assertNotNull(result.error)
  }

  @Test
  fun `a detection still wins when another probe failed`() {
    val result = Detection.run {
      signal("A", NativeConfidence.MEDIUM) { true }
      signal("B", NativeConfidence.HIGH) { fail() }
    }
    assertEquals(NativeDetectionStatus.DETECTED, result.status)
    assertEquals("B: probe failed", result.error)
  }

  @Test
  fun `an exception outside any probe becomes an error result`() {
    val result = Detection.run { throw IllegalStateException("boom") }
    assertEquals(NativeDetectionStatus.ERROR, result.status)
    assertEquals("boom", result.error)
  }

  @Test
  fun `umbrella results merge reasons and ignore unsupported parts`() {
    val detected = Detection.run { signal("FRIDA", NativeConfidence.HIGH) { true } }
    val clean = Detection.run { signal("XPOSED", NativeConfidence.HIGH) { false } }
    val result = Detection.run {
      include(detected)
      include(clean)
      include(Detection.unsupported())
    }
    assertEquals(NativeDetectionStatus.DETECTED, result.status)
    assertArrayEquals(arrayOf("FRIDA"), result.reasons)
  }

  @Test
  fun `umbrella of partially failed clean parts stays not_detected at low confidence`() {
    val partial = Detection.run {
      signal("A", NativeConfidence.HIGH) { false }
      signal("B", NativeConfidence.HIGH) { fail() }
    }
    val result = Detection.run {
      include(partial)
      include(partial)
    }
    assertEquals(NativeDetectionStatus.NOT_DETECTED, result.status)
    assertEquals(NativeConfidence.LOW, result.confidence)
  }

  @Test
  fun `umbrella of only failed parts is an error`() {
    val failed = Detection.run { signal("A", NativeConfidence.HIGH) { fail() } }
    val result = Detection.run { include(failed) }
    assertEquals(NativeDetectionStatus.ERROR, result.status)
  }

  @Test
  fun `a detector with nothing to run is unsupported`() {
    assertEquals(NativeDetectionStatus.UNSUPPORTED, Detection.run { }.status)
  }

  @Test
  fun `not configured carries its reason code`() {
    val result = Detection.notConfigured("SIGNATURE_HASH_NOT_CONFIGURED")
    assertEquals(NativeDetectionStatus.NOT_CONFIGURED, result.status)
    assertArrayEquals(arrayOf("SIGNATURE_HASH_NOT_CONFIGURED"), result.reasons)
  }
}
