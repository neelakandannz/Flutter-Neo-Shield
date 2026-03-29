import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Flutter/Dart Specific';

/// Rules for detecting Flutter and Dart specific security issues.
List<ScanRule> flutterSpecificRules() => [
      // 84. Unprotected Platform Channels
      ScanRule(
        id: 'FLT001',
        category: _cat,
        severity: Severity.medium,
        title: 'MethodChannel without input validation',
        description:
            'MethodChannel invokeMethod with dynamic arguments — validate native-side inputs.',
        recommendation:
            'Validate and type-check all arguments passed through platform channels.',
        pattern: RegExp(
          r'''MethodChannel\s*\(\s*['"][^'"]+['"]\s*\)[\s\S]{0,500}invokeMethod''',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'flutter_neo_shield'),
          RegExp(r'ShieldCodec'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 85. State Exposure in App Switcher
      ScanRule(
        id: 'FLT002',
        category: _cat,
        severity: Severity.medium,
        title: 'AppLifecycleState handler without screen protection',
        description:
            'App detects lifecycle state but does not protect screen in app switcher.',
        recommendation:
            'Use ScreenShield.enableAppSwitcherGuard() or ScreenShieldScope widget.',
        pattern: RegExp(
          r'AppLifecycleState\.(paused|inactive|hidden)',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'ScreenShield'),
          RegExp(r'screen_shield'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 86. Insecure WebView JavaScript Bridge
      ScanRule(
        id: 'FLT003',
        category: _cat,
        severity: Severity.high,
        title: 'WebView JavaScript channel without origin check',
        description:
            'JavascriptChannel registered without validating message origin.',
        recommendation:
            'Validate the origin of messages received through JavaScript channels. Use WebViewShield.',
        pattern: RegExp(
          r'JavascriptChannel\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'origin'),
          RegExp(r'WebViewShield'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 87. Global Mutable Sensitive State
      ScanRule(
        id: 'FLT004',
        category: _cat,
        severity: Severity.medium,
        title: 'Global mutable variable holding sensitive data',
        description:
            'Top-level or static mutable variable may hold sensitive data without memory protection.',
        recommendation:
            'Use MemoryShield SecureString/SecureBytes for sensitive data in singletons.',
        pattern: RegExp(
          r'''(static\s+)?(?:String|List<int>)\s+(token|password|secret|apiKey|sessionId|accessToken)\s*=''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'SecureString'),
          RegExp(r'MemoryShield'),
          RegExp(r'_test\.dart$'),
          RegExp(r'const\s'),
          RegExp(r'final\s'),
        ],
      ),

      // 88. Async Gap (mounted check)
      ScanRule(
        id: 'FLT005',
        category: _cat,
        severity: Severity.low,
        title: 'Missing mounted check after await in StatefulWidget',
        description:
            'setState or context used after await without checking mounted — may cause errors.',
        recommendation:
            'Add "if (!mounted) return;" after every await in State methods.',
        pattern: RegExp(
          r'await\s+[\w.]+\s*\([^)]*\)\s*;\s*\n\s*(setState|Navigator|ScaffoldMessenger|showDialog)',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'mounted'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 89. Unprotected Deep Link Routes
      ScanRule(
        id: 'FLT006',
        category: _cat,
        severity: Severity.medium,
        title: 'Deep link route without auth guard',
        description:
            'Route registered for deep links without authentication middleware.',
        recommendation:
            'Add authentication guards to all deep link routes.',
        pattern: RegExp(
          r'''(onGenerateRoute|GoRouter|MaterialApp\.router)[\s\S]{0,500}(path:\s*['"][/:][\w/:]+['"])''',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'auth'),
          RegExp(r'guard'),
          RegExp(r'redirect'),
          RegExp(r'login'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 90. Insecure WebView Configuration
      ScanRule(
        id: 'FLT007',
        category: _cat,
        severity: Severity.high,
        title: 'WebView with JavaScript enabled and file access',
        description:
            'WebView with both JavaScript and file access enabled — allows local file exfiltration.',
        recommendation:
            'Disable file access in WebView. Use WebViewShield.recommendedSettings.',
        pattern: RegExp(
          r'(javaScriptMode:\s*JavaScriptMode\.unrestricted|javascriptEnabled:\s*true)[\s\S]{0,300}(allowsFileAccess|allowFileAccess|allowUniversalAccessFromFileURLs)',
        ),
        fileExtensions: ['.dart'],
      ),
    ];
