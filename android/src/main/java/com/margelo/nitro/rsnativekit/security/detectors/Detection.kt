package com.margelo.nitro.rsnativekit.security.detectors

import com.margelo.nitro.rsnativekit.security.NativeConfidence
import com.margelo.nitro.rsnativekit.security.NativeDetectionResult
import com.margelo.nitro.rsnativekit.security.NativeDetectionStatus

/**
 * Collects the individual signals of one detector into a [NativeDetectionResult].
 *
 * Each probe passed to [signal] must *throw* when it can't determine an answer
 * (unreadable file, missing service, ...) rather than return `false` — that's
 * what lets a failed check surface as `error` / low confidence instead of
 * silently reading as "not detected".
 */
internal class Detection {
  private val reasons = mutableListOf<String>()
  private val failures = mutableListOf<String>()

  /** Failures inside an included result that still reached a verdict — lower confidence only. */
  private val partialFailures = mutableListOf<String>()
  private var attempted = 0
  private var strongest: NativeConfidence? = null

  fun signal(code: String, confidence: NativeConfidence, probe: () -> Boolean) {
    attempted++
    try {
      if (probe()) {
        reasons += code
        raise(confidence)
      }
    } catch (e: Throwable) {
      failures += "$code: ${e.message ?: e.javaClass.simpleName}"
    }
  }

  /** Merges another detector's result, e.g. for umbrella checks like `hooks`. */
  fun include(result: NativeDetectionResult) {
    when (result.status) {
      NativeDetectionStatus.DETECTED -> {
        attempted++
        reasons += result.reasons
        raise(result.confidence)
        result.error?.let { partialFailures += it }
      }
      NativeDetectionStatus.ERROR -> {
        attempted++
        failures += result.error ?: "unknown error"
      }
      NativeDetectionStatus.NOT_DETECTED -> {
        attempted++
        result.error?.let { partialFailures += it }
      }
      NativeDetectionStatus.UNSUPPORTED, NativeDetectionStatus.NOT_CONFIGURED -> Unit
    }
  }

  private fun raise(confidence: NativeConfidence) {
    val current = strongest
    if (current == null || confidence.ordinal > current.ordinal) strongest = confidence
  }

  fun result(): NativeDetectionResult {
    val allFailures = failures + partialFailures
    val errorText = allFailures.takeIf { it.isNotEmpty() }?.joinToString("; ")
    return when {
      reasons.isNotEmpty() ->
        NativeDetectionResult(
          NativeDetectionStatus.DETECTED,
          reasons.distinct().toTypedArray(),
          strongest ?: NativeConfidence.LOW,
          errorText
        )
      attempted == 0 -> unsupported()
      failures.size >= attempted ->
        NativeDetectionResult(NativeDetectionStatus.ERROR, emptyArray(), NativeConfidence.LOW, errorText)
      else -> NativeDetectionResult(
        NativeDetectionStatus.NOT_DETECTED,
        emptyArray(),
        // On-device checks can be hidden from, so "not detected" never claims high confidence.
        if (allFailures.isEmpty()) NativeConfidence.MEDIUM else NativeConfidence.LOW,
        errorText
      )
    }
  }

  companion object {
    fun run(block: Detection.() -> Unit): NativeDetectionResult {
      return try {
        Detection().apply(block).result()
      } catch (e: Throwable) {
        failed(e)
      }
    }

    fun unsupported(): NativeDetectionResult =
      NativeDetectionResult(NativeDetectionStatus.UNSUPPORTED, emptyArray(), NativeConfidence.HIGH, null)

    fun notConfigured(code: String): NativeDetectionResult =
      NativeDetectionResult(NativeDetectionStatus.NOT_CONFIGURED, arrayOf(code), NativeConfidence.HIGH, null)

    fun failed(e: Throwable): NativeDetectionResult =
      NativeDetectionResult(NativeDetectionStatus.ERROR, emptyArray(), NativeConfidence.LOW, e.message ?: e.javaClass.simpleName)  }
}

internal val NativeDetectionResult.isDetected: Boolean
  get() = status == NativeDetectionStatus.DETECTED
