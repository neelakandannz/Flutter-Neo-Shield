import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Privacy & Compliance';

/// Rules for detecting privacy and compliance issues.
List<ScanRule> privacyRules() => [
      // 71. PII in Logs
      ScanRule(
        id: 'PRV001',
        category: _cat,
        severity: Severity.high,
        title: 'PII pattern in print/log statement',
        description:
            'Email, phone, SSN, or other PII found in print/log statements.',
        recommendation:
            'Use shieldLog() from LogShield instead of print(). It auto-redacts PII in release builds.',
        pattern: RegExp(
          r'''(print|debugPrint|log|logger\.\w+)\s*\([^)]*?(['"`][^'"`]*@[^'"`]*\.[^'"`]*['"`]|\d{3}-\d{2}-\d{4}|\d{3}-\d{3}-\d{4})''',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'_test\.dart$'),
          RegExp(r'shieldLog'),
        ],
      ),

      // 72. PII in Error Messages
      ScanRule(
        id: 'PRV002',
        category: _cat,
        severity: Severity.medium,
        title: 'User data in exception/error message',
        description:
            'Exception messages may contain user data that ends up in crash reporting.',
        recommendation:
            'Use error codes in exceptions instead of user data. Log details via shieldLog().',
        pattern: RegExp(
          r'''(throw\s+\w*Exception|Exception|Error)\s*\([^)]*?\$\{?[a-z]*(user|email|name|phone|address)''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 73. Missing Data Retention
      ScanRule(
        id: 'PRV003',
        category: _cat,
        severity: Severity.low,
        title: 'Cached data without cleanup strategy',
        description:
            'Data cached without clear TTL or cleanup mechanism.',
        recommendation:
            'Implement cache expiry. Use MemoryShield with maxAge for in-memory data.',
        pattern: RegExp(
          r'(cache|Cache)\s*[\[.]\s*(put|set|add|insert)\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'expir'),
          RegExp(r'ttl'),
          RegExp(r'duration'),
          RegExp(r'maxAge'),
        ],
      ),

      // 74. Analytics without Consent
      ScanRule(
        id: 'PRV004',
        category: _cat,
        severity: Severity.medium,
        title: 'Analytics initialized without consent check',
        description:
            'Analytics/tracking SDK initialized without checking user consent (GDPR/CCPA).',
        recommendation:
            'Check for user consent before initializing analytics. Implement opt-in/opt-out.',
        pattern: RegExp(
          r'(FirebaseAnalytics|Amplitude|Mixpanel|FlutterAmplitude|Analytics)\.(init|instance|getInstance)\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'consent'),
          RegExp(r'gdpr'),
          RegExp(r'opt[_-]?in'),
          RegExp(r'permission'),
        ],
      ),

      // 75. Device Fingerprinting
      ScanRule(
        id: 'PRV005',
        category: _cat,
        severity: Severity.medium,
        title: 'Device identifier collection',
        description:
            'IMEI, UDID, or advertising ID collected — may require user disclosure.',
        recommendation:
            'Disclose device fingerprinting in privacy policy. Use DeviceBindingShield for privacy-respecting binding.',
        pattern: RegExp(
          r'(IMEI|UDID|advertisingId|idfa|gaid|android[_.]?id|getAndroidId|identifierForVendor)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart', '.kt', '.swift'],
        exclusions: [
          RegExp(r'device_binding_shield'),
        ],
      ),

      // 76. Clipboard PII Exposure
      ScanRule(
        id: 'PRV006',
        category: _cat,
        severity: Severity.medium,
        title: 'Clipboard write without auto-clear',
        description:
            'Clipboard.setData used without auto-clear — PII stays on clipboard indefinitely.',
        recommendation:
            'Use ClipboardShield.copy() which auto-clears clipboard after a timeout.',
        pattern: RegExp(
          r'Clipboard\.setData\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'ClipboardShield'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 77. Screenshot Exposure
      ScanRule(
        id: 'PRV007',
        category: _cat,
        severity: Severity.low,
        title: 'Sensitive screen without screenshot protection',
        description:
            'Screens displaying PII/financial data should use ScreenShield or ScreenShieldScope.',
        recommendation:
            'Wrap sensitive screens with ScreenShieldScope widget.',
        pattern: RegExp(
          r'(balance|creditCard|ssn|socialSecurity|bankAccount|medicalRecord|healthData)\b',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'ScreenShield'),
          RegExp(r'_test\.dart$'),
          RegExp(r'[/\\]models?[/\\]'),
          RegExp(r'[/\\]entit(?:y|ies)[/\\]'),
          RegExp(r'_model\.dart$'),
          RegExp(r'_entity\.dart$'),
        ],
      ),
    ];
