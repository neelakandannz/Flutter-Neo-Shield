import UIKit

/// Prevents screenshots and screen recording on iOS using the secure UITextField layer trick.
///
/// When enabled, the app's content is rendered through a layer associated with a
/// `UITextField` whose `isSecureTextEntry` is `true`. The OS treats this content
/// as DRM-protected and replaces it with a blank area during capture.
///
/// The technique works by finding the internal secure layer that iOS creates
/// inside a secure text field, then reparenting the window's root view layer
/// into that secure container. This causes iOS to blank the content during
/// screenshots and screen recordings.
class ScreenProtector {
    private var secureField: UITextField?
    private var isEnabled = false
    private weak var protectedWindow: UIWindow?

    /// Enable screen protection on the given window.
    func enable(in window: UIWindow?) -> Bool {
        guard let window = window, !isEnabled else { return isEnabled }

        DispatchQueue.main.async { [weak self] in
            self?.setupSecureField(in: window)
        }
        isEnabled = true
        return true
    }

    /// Disable screen protection.
    func disable() -> Bool {
        guard isEnabled else { return true }

        DispatchQueue.main.async { [weak self] in
            self?.teardownSecureField()
        }
        isEnabled = false
        return true
    }

    /// Whether screen protection is currently active.
    var isActive: Bool {
        return isEnabled
    }

    private func setupSecureField(in window: UIWindow) {
        // Clean up any existing secure field first.
        teardownSecureField()

        let field = UITextField()
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
        field.translatesAutoresizingMaskIntoConstraints = false

        // Add field to the window hierarchy.
        window.addSubview(field)

        // Pin to zero size — we only need its internal secure layer.
        NSLayoutConstraint.activate([
            field.centerYAnchor.constraint(equalTo: window.centerYAnchor),
            field.centerXAnchor.constraint(equalTo: window.centerXAnchor),
            field.widthAnchor.constraint(equalToConstant: 0),
            field.heightAnchor.constraint(equalToConstant: 0),
        ])

        // The secure text field creates an internal layer that iOS blanks
        // during capture. Reparent the root view's layer into that secure
        // container so all app content inherits the protection.
        guard let rootView = window.rootViewController?.view else {
            field.removeFromSuperview()
            return
        }

        if let secureLayer = field.layer.sublayers?.first {
            secureLayer.addSublayer(rootView.layer)
        }

        secureField = field
        protectedWindow = window
    }

    private func teardownSecureField() {
        guard let field = secureField else { return }

        // Restore the root view's layer back to the window's layer.
        if let window = protectedWindow ?? field.superview as? UIWindow,
           let rootView = window.rootViewController?.view {
            // Only restore if the root view's layer was reparented.
            if rootView.layer.superlayer !== window.layer {
                window.layer.addSublayer(rootView.layer)
                rootView.frame = window.bounds
                rootView.setNeedsLayout()
                rootView.layoutIfNeeded()
            }
        }

        field.isSecureTextEntry = false
        field.removeFromSuperview()
        secureField = nil
        protectedWindow = nil
    }
}
