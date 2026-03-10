import Foundation

/// Detects code signature tampering and sideloading on iOS.
///
/// When an attacker decrypts an IPA, modifies it, and re-signs with
/// a different certificate, the code signature changes. This detector
/// verifies multiple integrity signals.
///
/// Named SignatureDetector_P0 to avoid collision with future naming.
public class SignatureDetectorP0 {

    /// Returns true if code signature anomalies are detected.
    public static func check() -> Bool {
        return checkBundleIntegrity() ||
               checkMobileProvision() ||
               checkEntitlements() ||
               checkDYLDEnvironment()
    }

    /// Verifies the app bundle hasn't been modified.
    ///
    /// After repackaging, the Info.plist CFBundleIdentifier or
    /// executable name may differ from what was compiled.
    private static func checkBundleIntegrity() -> Bool {
        // Check if _CodeSignature directory exists and is intact
        let bundlePath = Bundle.main.bundlePath
        let codeSignPath = bundlePath + "/_CodeSignature"
        let codeResPath = codeSignPath + "/CodeResources"

        // Missing CodeResources means tampered or unsigned
        if !FileManager.default.fileExists(atPath: codeResPath) {
            // On simulator this doesn't exist, so check if we're on simulator
            #if targetEnvironment(simulator)
            return false
            #else
            return true
            #endif
        }

        // Verify the CodeResources plist is parseable (corrupted = tampered)
        guard let data = FileManager.default.contents(atPath: codeResPath),
              let _ = try? PropertyListSerialization.propertyList(
                  from: data,
                  options: [],
                  format: nil
              ) as? [String: Any] else {
            #if targetEnvironment(simulator)
            return false
            #else
            return true
            #endif
        }

        return false
    }

    /// Checks mobile provision for suspicious indicators.
    ///
    /// Re-signed apps have a different provisioning profile.
    /// We check for the existence and basic structure.
    private static func checkMobileProvision() -> Bool {
        let provisionPath = Bundle.main.bundlePath + "/embedded.mobileprovision"

        // On the App Store, mobileprovision is stripped.
        // Its presence on a non-TestFlight build is suspicious.
        let isTestFlight = Bundle.main.appStoreReceiptURL?
            .lastPathComponent == "sandboxReceipt"

        if FileManager.default.fileExists(atPath: provisionPath) {
            // Read provision to check for suspicious Team IDs
            if let data = FileManager.default.contents(atPath: provisionPath) {
                let content = String(data: data, encoding: .ascii) ?? ""

                // Look for known re-signing tools markers
                let suspiciousMarkers = [
                    "iPhone Distribution: iPhone Distribution",
                    "get-task-allow</key>\n\t<true/>",
                    "get-task-allow</key>\n\t\t<true/>"
                ]

                for marker in suspiciousMarkers {
                    if content.contains(marker) {
                        return true
                    }
                }
            }

            // If not TestFlight and has mobileprovision, it's sideloaded
            if !isTestFlight {
                // This is already handled by IntegrityDetector,
                // but we add get-task-allow check as extra signal
                return false
            }
        }

        return false
    }

    /// Checks for get-task-allow entitlement in production.
    ///
    /// This entitlement allows debugging. In production App Store builds,
    /// it should be false. Re-signed apps often have it set to true.
    private static func checkEntitlements() -> Bool {
        // Check for get-task-allow via embedded provision
        let provisionPath = Bundle.main.bundlePath + "/embedded.mobileprovision"
        guard FileManager.default.fileExists(atPath: provisionPath),
              let data = FileManager.default.contents(atPath: provisionPath) else {
            return false
        }

        let content = String(data: data, encoding: .ascii) ?? ""

        // If get-task-allow is true, debugging is allowed (suspicious in production)
        if content.contains("get-task-allow</key>") {
            // Find the value after the key
            if let range = content.range(of: "get-task-allow</key>") {
                let after = content[range.upperBound...]
                let trimmed = after.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.hasPrefix("<true/>") {
                    return true
                }
            }
        }

        return false
    }

    /// Checks for DYLD_INSERT_LIBRARIES environment variable.
    ///
    /// This is used to inject dylibs into the process, commonly used
    /// by reverse engineering tools on jailbroken devices.
    private static func checkDYLDEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment

        // DYLD_INSERT_LIBRARIES is the primary injection vector
        if env["DYLD_INSERT_LIBRARIES"] != nil {
            return true
        }

        // DYLD_LIBRARY_PATH can redirect library loads
        if env["DYLD_LIBRARY_PATH"] != nil {
            return true
        }

        // DYLD_FRAMEWORK_PATH can redirect framework loads
        if env["DYLD_FRAMEWORK_PATH"] != nil {
            return true
        }

        return false
    }
}
