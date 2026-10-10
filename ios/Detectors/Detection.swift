import Foundation

/// Collects the individual signals of one detector into a `NativeDetectionResult`.
///
/// Each probe passed to `signal` must *throw* when it can't determine an
/// answer rather than return `false` — that's what lets a failed check
/// surface as `error` / low confidence instead of silently reading as
/// "not detected". Mirrors Android's `Detection.kt`.
final class Detection {
  private var reasons: [String] = []
  private var failures: [String] = []
  /// Failures inside an included result that still reached a verdict — lower confidence only.
  private var partialFailures: [String] = []
  private var attempted = 0
  private var strongest: NativeConfidence?

  func signal(_ code: String, _ confidence: NativeConfidence, _ probe: () throws -> Bool) {
    attempted += 1
    do {
      if try probe() {
        reasons.append(code)
        raise(confidence)
      }
    } catch {
      failures.append("\(code): \(error.localizedDescription)")
    }
  }

  /// Merges another detector's result, e.g. for umbrella checks like `hooks`.
  func include(_ result: NativeDetectionResult) {
    switch result.status {
    case .detected:
      attempted += 1
      reasons.append(contentsOf: result.reasons)
      raise(result.confidence)
      if let error = result.error { partialFailures.append(error) }
    case .error:
      attempted += 1
      failures.append(result.error ?? "unknown error")
    case .notDetected:
      attempted += 1
      if let error = result.error { partialFailures.append(error) }
    default:
      break // unsupported / not_configured contribute nothing
    }
  }

  private func raise(_ confidence: NativeConfidence) {
    if let current = strongest, current.rawValue >= confidence.rawValue { return }
    strongest = confidence
  }

  func result() -> NativeDetectionResult {
    let allFailures = failures + partialFailures
    let errorText = allFailures.isEmpty ? nil : allFailures.joined(separator: "; ")
    if !reasons.isEmpty {
      var unique: [String] = []
      for reason in reasons where !unique.contains(reason) { unique.append(reason) }
      return NativeDetectionResult(status: .detected, reasons: unique, confidence: strongest ?? .low, error: errorText)
    }
    if attempted == 0 { return Detection.unsupported() }
    if failures.count >= attempted {
      return NativeDetectionResult(status: .error, reasons: [], confidence: .low, error: errorText)
    }
    // On-device checks can be hidden from, so "not detected" never claims high confidence.
    return NativeDetectionResult(
      status: .notDetected,
      reasons: [],
      confidence: allFailures.isEmpty ? .medium : .low,
      error: errorText
    )
  }

  static func run(_ block: (Detection) throws -> Void) -> NativeDetectionResult {
    let detection = Detection()
    do {
      try block(detection)
      return detection.result()
    } catch {
      return failed(error)
    }
  }

  static func unsupported() -> NativeDetectionResult {
    NativeDetectionResult(status: .unsupported, reasons: [], confidence: .high, error: nil)
  }

  static func notConfigured(_ code: String) -> NativeDetectionResult {
    NativeDetectionResult(status: .notConfigured, reasons: [code], confidence: .high, error: nil)
  }

  static func failed(_ error: Error) -> NativeDetectionResult {
    NativeDetectionResult(status: .error, reasons: [], confidence: .low, error: error.localizedDescription)
  }
}

extension NativeDetectionResult {
  var isDetected: Bool { status == .detected }
}

struct DetectionError: LocalizedError {
  let errorDescription: String?
  init(_ message: String) { errorDescription = message }
}
