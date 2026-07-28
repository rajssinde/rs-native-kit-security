import Foundation
import MachO

/// Shared helper for scanning the process's currently-loaded dynamic
/// libraries (`_dyld_image_count`/`_dyld_get_image_name`) for substrings
/// associated with jailbreak tweak injectors and instrumentation
/// frameworks. Used by both `JailbreakDetector` and `HookDetector`.
enum DylibScanner {
  static func loadedImageNames() -> [String] {
    let count = _dyld_image_count()
    var names: [String] = []
    names.reserveCapacity(Int(count))
    for i in 0..<count {
      guard let cName = _dyld_get_image_name(i) else { continue }
      names.append(String(cString: cName))
    }
    return names
  }

  static func anyLoadedImageContains(_ markers: [String]) -> Bool {
    let images = loadedImageNames()
    return images.contains { image in
      markers.contains { marker in image.localizedCaseInsensitiveContains(marker) }
    }
  }
}
