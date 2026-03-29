import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Authentication & Session Flaws';

/// Rules for detecting authentication and session flaws.
List<ScanRule> authSessionRules() => [
      // 41. Biometric without Crypto
      ScanRule(
        id: 'AUTH001',
        category: _cat,
        severity: Severity.high,
        title: 'Biometric auth without cryptographic binding',
        description:
            'local_auth used without cryptographic key binding. Biometric result is a simple boolean — easily bypassed with Frida.',
        recommendation:
            'Use BiometricShield with crypto-bound authentication, or bind biometric to a Keystore key.',
        pattern: RegExp(
          r'(LocalAuthentication|local_auth)[\s\S]{0,300}authenticate\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'BiometricShield'),
        ],
      ),

      // 42. Session Token in URL
      ScanRule(
        id: 'AUTH002',
        category: _cat,
        severity: Severity.high,
        title: 'Token passed in URL query parameter',
        description:
            'Authentication token passed as URL query parameter — visible in logs, referrer headers, browser history.',
        recommendation:
            'Pass tokens in Authorization header, not URL parameters.',
        pattern: RegExp(
          r'''(url|uri|endpoint|href)[\s\S]{0,50}[?&](token|api_key|apikey|access_token|session_id|auth)=''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 43. Missing Token Expiry
      ScanRule(
        id: 'AUTH003',
        category: _cat,
        severity: Severity.medium,
        title: 'Token stored without expiry check',
        description:
            'Token stored persistently without expiry validation. Stale tokens are a security risk.',
        recommendation:
            'Always check token expiry before use. Implement refresh token flow.',
        pattern: RegExp(
          r'(setString|write|save|store)\s*\([^)]*?(access_token|refresh_token|auth_token|session_token)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'expir'),
          RegExp(r'ttl'),
          RegExp(r'maxAge'),
        ],
      ),

      // 44. Insecure Deep Links
      ScanRule(
        id: 'AUTH004',
        category: _cat,
        severity: Severity.high,
        title: 'Deep link parameter used without validation',
        description:
            'Deep link/URI parameters used directly without sanitization — injection risk.',
        recommendation:
            'Validate and sanitize all deep link parameters. Use DlpShield.sanitizeDeepLink().',
        customCheck: (path, content) {
          if (!path.endsWith('.dart')) return [];
          final matches = <RuleMatch>[];
          final pattern = RegExp(r'(queryParameters|pathSegments)\[');
          const validationKeywords = [
            'valid', 'sanitiz', 'check', 'verify', 'DlpShield',
          ];
          final lines = content.split('\n');
          for (var i = 0; i < lines.length; i++) {
            if (!pattern.hasMatch(lines[i])) continue;
            // Check current line and surrounding 3 lines for validation
            var hasValidation = false;
            for (var j = (i - 3).clamp(0, lines.length);
                j < (i + 4).clamp(0, lines.length);
                j++) {
              final line = lines[j].toLowerCase();
              for (final kw in validationKeywords) {
                if (line.contains(kw.toLowerCase())) {
                  hasValidation = true;
                  break;
                }
              }
              if (hasValidation) break;
            }
            if (!hasValidation) {
              matches.add(RuleMatch(
                lineNumber: i + 1,
                matchedText: lines[i].trim(),
              ));
            }
          }
          return matches;
        },
        fileExtensions: ['.dart'],
      ),

      // 45. Missing Input Validation
      ScanRule(
        id: 'AUTH005',
        category: _cat,
        severity: Severity.medium,
        title: 'User input passed directly to API',
        description:
            'User-controlled input concatenated into API endpoint or request body without validation.',
        recommendation:
            'Validate, sanitize, and type-check all user input before API calls.',
        pattern: RegExp(
          r'''(http\.get|http\.post|dio\.(get|post|put|delete)|fetch)\s*\([^)]*?\$\{?[a-z]''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 46. Hardcoded User Credentials
      ScanRule(
        id: 'AUTH006',
        category: _cat,
        severity: Severity.critical,
        title: 'Hardcoded test/user credentials',
        description:
            'Test account credentials left in source code.',
        recommendation:
            'Remove all test credentials. Use environment-specific config.',
        pattern: RegExp(
          r'''(test_user|admin_password|default_password|demo_account)\s*[:=]\s*['"`][^'"`]+['"`]''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart', '.json', '.yaml'],
      ),

      // 47. Auto-Login without Device Binding
      ScanRule(
        id: 'AUTH007',
        category: _cat,
        severity: Severity.medium,
        title: 'Auto-login without device binding',
        description:
            'Stored credentials used for auto-login without device binding verification.',
        recommendation:
            'Use DeviceBindingShield.validateBinding() before auto-login.',
        pattern: RegExp(
          r'(auto[_]?login|remember[_]?me|stay[_]?logged)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'DeviceBinding'),
          RegExp(r'deviceFingerprint'),
        ],
      ),
    ];
