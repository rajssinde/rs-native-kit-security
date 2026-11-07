import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// iOS counterpart of Android's `FLAG_SECURE`, within what iOS allows: there
/// is no public API to block screenshots, but the app's content can be kept
/// out of screen recordings, AirPlay/mirroring and the app-switcher snapshot
/// by covering it with an opaque window while the screen is captured or the
/// app is resigning active.
final class ScreenShield {
  #if canImport(UIKit) && !os(watchOS)
  private var enabled = false
  private var resigningActive = false
  private var coverWindow: UIWindow?
  private var observers: [NSObjectProtocol] = []

  /// Must be called on the main thread.
  func setEnabled(_ enabled: Bool) {
    guard enabled != self.enabled else { return }
    self.enabled = enabled
    if enabled {
      let center = NotificationCenter.default
      observers = [
        center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
          self?.update()
        },
        center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
          self?.resigningActive = true
          self?.update()
        },
        center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
          self?.resigningActive = false
          self?.update()
        },
      ]
    } else {
      observers.forEach { NotificationCenter.default.removeObserver($0) }
      observers = []
      resigningActive = false
    }
    update()
  }

  private func update() {
    let shouldCover = enabled && (resigningActive || UIScreen.main.isCaptured)
    if shouldCover {
      showCover()
    } else {
      coverWindow?.isHidden = true
      coverWindow = nil
    }
  }

  private func showCover() {
    if coverWindow != nil { return }
    guard let scene = UIApplication.shared.connectedScenes
      .compactMap({ $0 as? UIWindowScene })
      .first(where: { $0.activationState != .unattached })
    else { return }

    let window = UIWindow(windowScene: scene)
    window.windowLevel = .alert + 1
    let controller = UIViewController()
    let blur = UIVisualEffectView(effect: UIBlurEffect(style: .systemThickMaterial))
    blur.frame = window.bounds
    blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    controller.view.backgroundColor = .systemBackground
    controller.view.addSubview(blur)
    window.rootViewController = controller
    window.isHidden = false
    coverWindow = window
  }
  #else
  func setEnabled(_ enabled: Bool) {}
  #endif
}
