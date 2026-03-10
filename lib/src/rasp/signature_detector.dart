import '../platform/rasp_channel.dart';
import 'security_result.dart';

/// Detects APK/IPA repackaging by verifying the signing certificate
/// and binary integrity at the native level.
///
/// On Android: Verifies APK signing certificate hash, checks for debug
/// certificates, and optionally validates classes.dex hashes.
///
/// On iOS: Verifies code signature integrity, checks for DYLD injection
/// environment variables, and validates entitlements.
///
/// This is the **#1 defense against APK repackaging** — the most common
/// desktop-based reverse engineering attack.
class SignatureDetector {
  /// Executes the signature verification check on the native platform.
  ///
  /// Optionally provide [expectedSignatureHash] (SHA-256 of your signing
  /// certificate) for strict verification. Without it, heuristic checks
  /// are used (debug cert detection, multiple signers).
  ///
  /// Use [RaspShield.getSignatureHash()] to obtain your app's current
  /// signing certificate hash during development.
  static Future<SecurityResult> check() async {
    final isDetected =
        await RaspChannel.invokeDetection('checkSignature');
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected
          ? 'APK/IPA signature anomaly detected (possible repackaging)'
          : null,
    );
  }

  /// Returns the current app's signing certificate SHA-256 hash.
  ///
  /// Call this during development to obtain the hash, then embed it
  /// in your app for runtime verification.
  ///
  /// Returns null on platforms that don't support this.
  static Future<String?> getSignatureHash() async {
    try {
      final hash =
          await RaspChannel.invokeStringMethod('getSignatureHash');
      return hash;
    } catch (e) {
      return null;
    }
  }
}
