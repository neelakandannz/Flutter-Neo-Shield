/// Client-side security & PII protection toolkit for Flutter.
///
/// 27 shields + CLI security scanner covering runtime protection, data security,
/// input safety, network hardening, and privacy compliance — native on all 6 platforms.
/// Run `dart run flutter_neo_shield:scan` for static security analysis.
///
/// ```dart
/// import 'package:flutter_neo_shield/flutter_neo_shield.dart';
///
/// void main() {
///   WidgetsFlutterBinding.ensureInitialized();
///   FlutterNeoShield.init();
///   runApp(MyApp());
/// }
/// ```
library flutter_neo_shield;

// Core
export 'src/core/pii_detector.dart';
export 'src/core/pii_pattern.dart';
export 'src/core/pii_type.dart';
export 'src/core/shield_config.dart';
export 'src/core/shield_report.dart';

// Log Shield
export 'src/log_shield/json_sanitizer.dart';
export 'src/log_shield/log_shield.dart';
export 'src/log_shield/log_shield_config.dart';
export 'src/log_shield/safe_log.dart';

// Clipboard Shield
export 'src/clipboard_shield/clipboard_copy_result.dart';
export 'src/clipboard_shield/clipboard_shield.dart';
export 'src/clipboard_shield/clipboard_shield_config.dart';
export 'src/clipboard_shield/secure_copy.dart';
export 'src/clipboard_shield/secure_copy_button.dart';
export 'src/clipboard_shield/secure_paste_field.dart';

// Memory Shield
export 'src/memory_shield/memory_shield.dart';
export 'src/memory_shield/memory_shield_config.dart';
export 'src/memory_shield/secure_bytes.dart';
export 'src/memory_shield/secure_string.dart';
export 'src/memory_shield/secure_value.dart';

// String Shield
export 'src/string_shield/annotations.dart';
export 'src/string_shield/deobfuscator.dart';
export 'src/string_shield/obfuscation_strategy.dart';
export 'src/string_shield/string_shield.dart';
export 'src/string_shield/string_shield_config.dart';

// RASP Shield
export 'src/rasp/rasp_shield.dart';
export 'src/rasp/security_mode.dart';
export 'src/rasp/security_result.dart';

// Screen Shield
export 'src/screen_shield/screen_shield.dart';
export 'src/screen_shield/screen_shield_callback.dart';
export 'src/screen_shield/screen_shield_config.dart';
export 'src/screen_shield/screen_shield_widget.dart';

// Location Shield
export 'src/location_shield/location_shield.dart';
export 'src/location_shield/location_result.dart';

// --- New Shields (v2.0.0) ---

// Overlay Shield
export 'src/overlay_shield/overlay_shield.dart';
export 'src/overlay_shield/overlay_shield_config.dart';

// Accessibility Shield
export 'src/accessibility_shield/accessibility_shield.dart';

// Secure Input Shield
export 'src/secure_input_shield/secure_input_shield.dart';

// Certificate Pinning Shield
export 'src/cert_pin_shield/cert_pin_shield.dart';

// WebView Shield
export 'src/webview_shield/webview_shield.dart';

// Secure Storage Shield
export 'src/secure_storage_shield/secure_storage_shield.dart';

// Biometric Shield
export 'src/biometric_shield/biometric_shield.dart';

// Encryption Shield
export 'src/encryption_shield/encryption_shield.dart';

// RASP Monitor
export 'src/rasp_monitor/rasp_monitor.dart';

// Threat Response
export 'src/threat_response/threat_response.dart';

// Device Binding Shield
export 'src/device_binding_shield/device_binding_shield.dart';

// DNS Shield
export 'src/dns_shield/dns_shield.dart';

// TLS Shield
export 'src/tls_shield/tls_shield.dart';

// Permission Shield
export 'src/permission_shield/permission_shield.dart';

// DLP Shield
export 'src/dlp_shield/dlp_shield.dart';

// Watermark Shield
export 'src/watermark_shield/watermark_shield.dart';

// Dependency Shield
export 'src/dependency_shield/dependency_shield.dart';

// Code Injection Shield
export 'src/code_injection_shield/code_injection_shield.dart';

// Obfuscation Shield
export 'src/obfuscation_shield/obfuscation_shield.dart';

// Security Dashboard
export 'src/security_dashboard/security_dashboard.dart';

// Main
export 'src/flutter_neo_shield.dart';

// Desktop plugin stubs (required for dart_plugin_registrant)
export 'flutter_neo_shield_stub.dart';
