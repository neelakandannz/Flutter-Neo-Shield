import 'package:flutter/services.dart';
import 'dart:developer' as developer;

/// Handles communication between Flutter and Native layer for RASP checks.
///
/// Uses a fail-closed design: if the native platform is unavailable or
/// throws an error, checks report the threat as detected (safe default).
class RaspChannel {
  static const MethodChannel _channel =
      MethodChannel('com.neelakandan.flutter_neo_shield/rasp');

  static bool _failClosed = true;
  static bool _configured = false;

  /// Whether to fail closed (return true = detected) on platform errors.
  ///
  /// Defaults to true for security. Use [configure] to change this
  /// value before any checks are performed.
  static bool get failClosed => _failClosed;

  /// Configures the fail-closed behavior. Can only be called once.
  ///
  /// Set [failClosed] to false only in development when native plugins
  /// are not yet integrated.
  static void configure({required bool failClosed}) {
    if (_configured) return;
    _configured = true;
    _failClosed = failClosed;
  }

  /// Invoke a native detection method.
  ///
  /// Returns true (threat detected) when the platform channel is
  /// unavailable and [failClosed] is true, ensuring the app does not
  /// silently pass security checks on unsupported platforms.
  static Future<bool> invokeDetection(String method,
      [Map<String, dynamic>? arguments]) async {
    try {
      final result = await _channel.invokeMethod<bool>(method, arguments);
      return result ?? _failClosed;
    } on MissingPluginException {
      developer.log(
        '$method: native plugin not registered — '
        '${_failClosed ? "reporting as detected (fail-closed)" : "reporting as safe (fail-open)"}',
        name: 'RaspChannel',
      );
      return _failClosed;
    } on PlatformException catch (e) {
      developer.log('Failed to execute $method: ${e.message}',
          name: 'RaspChannel');
      return _failClosed;
    }
  }

  /// Invoke a native method that returns a String (or null).
  ///
  /// Used for methods like getSignatureHash that return data
  /// rather than a boolean detection result.
  static Future<String?> invokeStringMethod(String method,
      [Map<String, dynamic>? arguments]) async {
    try {
      final result =
          await _channel.invokeMethod<String>(method, arguments);
      return result;
    } on MissingPluginException {
      return null;
    } on PlatformException {
      return null;
    }
  }

  /// Resets configuration state. Only for testing.
  static void resetForTesting() {
    _failClosed = true;
    _configured = false;
  }
}
