import UIKit

/// Detects screen recording and mirroring state changes on iOS 11+.
///
/// Uses `UIScreen.isCaptured` and `capturedDidChangeNotification` to
/// monitor for screen recording, AirPlay mirroring, and other capture.
class ScreenRecordingDetector {
    private var observer: NSObjectProtocol?
    private var handler: ((Bool) -> Void)?

    /// Returns the primary UIScreen, preferring the modern UIWindowScene API
    /// on iOS 16+ and falling back to UIScreen.main on earlier versions.
    private var primaryScreen: UIScreen? {
        if #available(iOS 16.0, *) {
            return UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first?.screen
        }
        return UIScreen.main
    }

    /// Whether the screen is currently being captured (recorded or mirrored).
    var isRecording: Bool {
        if #available(iOS 11.0, *) {
            return primaryScreen?.isCaptured ?? false
        }
        return false
    }

    /// Whether an external display is connected (mirroring).
    var isMirrored: Bool {
        if #available(iOS 16.0, *) {
            return UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .count > 1
        }
        return UIScreen.screens.count > 1
    }

    /// Start detecting recording state changes.
    func startDetecting(handler: @escaping (Bool) -> Void) {
        stopDetecting()
        self.handler = handler

        if #available(iOS 11.0, *) {
            observer = NotificationCenter.default.addObserver(
                forName: UIScreen.capturedDidChangeNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                let isCaptured = self?.primaryScreen?.isCaptured ?? false
                self?.handler?(isCaptured)
            }
        }
    }

    /// Stop detecting recording state changes.
    func stopDetecting() {
        if let obs = observer {
            NotificationCenter.default.removeObserver(obs)
            observer = nil
        }
        handler = nil
    }

    deinit {
        stopDetecting()
    }
}
