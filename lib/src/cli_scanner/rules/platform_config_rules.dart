import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Platform Configuration Weaknesses';

/// Rules for detecting platform configuration weaknesses.
List<ScanRule> platformConfigRules() => [
      // 31. Debug Mode Missing Guards
      ScanRule(
        id: 'PLT001',
        category: _cat,
        severity: Severity.medium,
        title: 'Sensitive code without debug mode check',
        description:
            'Sensitive operations executed without kDebugMode/kReleaseMode guard.',
        recommendation:
            'Wrap debug-only code in if (kDebugMode) {} blocks.',
        pattern: RegExp(
          r"""(print|debugPrint)\s*\(\s*['"].*?(password|token|secret|key)""",
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'kDebugMode'),
          RegExp(r'kReleaseMode'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 32. Android Debuggable Flag
      ScanRule(
        id: 'PLT002',
        category: _cat,
        severity: Severity.critical,
        title: 'Android app marked as debuggable',
        description:
            'android:debuggable="true" in AndroidManifest.xml. Release builds must not be debuggable.',
        recommendation:
            'Remove android:debuggable="true" — Gradle sets it automatically per build type.',
        pattern: RegExp(
          r'android:debuggable\s*=\s*"true"',
        ),
        fileExtensions: ['.xml'],
      ),

      // 33. Android Exported Components
      ScanRule(
        id: 'PLT003',
        category: _cat,
        severity: Severity.high,
        title: 'Exported Android component without permission',
        description:
            'Activity/Service/Receiver exported without android:permission. '
            'Other apps can invoke it.',
        recommendation:
            'Add android:exported="false" or protect with a custom permission.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (!path.endsWith('.xml')) return matches;
          // Find each exported="true" and check if the surrounding component
          // block contains android:permission or is the MainActivity/LAUNCHER
          final exportedPattern =
              RegExp(r'android:exported\s*=\s*"true"');
          for (final m in exportedPattern.allMatches(content)) {
            // Get surrounding context (200 chars before and after)
            final startIdx = (m.start - 200).clamp(0, content.length);
            final endIdx = (m.end + 200).clamp(0, content.length);
            final block = content.substring(startIdx, endIdx);
            // Skip if it has a permission or is MainActivity/LAUNCHER
            if (block.contains('android:permission') ||
                block.contains('MainActivity') ||
                block.contains('.MAIN') ||
                block.contains('.LAUNCHER')) {
              continue;
            }
            final lineNumber =
                content.substring(0, m.start).split('\n').length;
            matches.add(RuleMatch(
              lineNumber: lineNumber,
              matchedText: 'android:exported="true" without permission',
            ));
          }
          return matches;
        },
        fileExtensions: ['.xml'],
      ),

      // 34. Android Backup Allowed
      ScanRule(
        id: 'PLT004',
        category: _cat,
        severity: Severity.high,
        title: 'Android backup enabled',
        description:
            'android:allowBackup="true" allows adb backup to extract app data including tokens.',
        recommendation:
            'Set android:allowBackup="false" or configure backup rules to exclude sensitive data.',
        pattern: RegExp(
          r'android:allowBackup\s*=\s*"true"',
        ),
        fileExtensions: ['.xml'],
      ),

      // 35. iOS ATS Exceptions
      ScanRule(
        id: 'PLT005',
        category: _cat,
        severity: Severity.high,
        title: 'iOS App Transport Security disabled',
        description:
            'NSAllowsArbitraryLoads is true — all HTTP traffic allowed on iOS.',
        recommendation:
            'Remove NSAllowsArbitraryLoads and add per-domain exceptions if needed.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (!path.endsWith('.plist')) return matches;
          final pattern = RegExp(
            r'<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>',
          );
          for (final m in pattern.allMatches(content)) {
            final lineNumber =
                content.substring(0, m.start).split('\n').length;
            matches.add(RuleMatch(
              lineNumber: lineNumber,
              matchedText: 'NSAllowsArbitraryLoads = true',
            ));
          }
          return matches;
        },
        fileExtensions: ['.plist'],
      ),

      // 36. iOS Insecure URL Schemes
      ScanRule(
        id: 'PLT006',
        category: _cat,
        severity: Severity.medium,
        title: 'Custom URL scheme without validation',
        description:
            'Custom URL scheme registered — ensure deep link parameters are validated.',
        recommendation:
            'Validate all deep link parameters. Use DlpShield.sanitizeDeepLink().',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (!path.endsWith('.plist')) return matches;
          final pattern = RegExp(
            r'<key>CFBundleURLSchemes</key>\s*<array>\s*<string>[a-z]+</string>',
          );
          for (final m in pattern.allMatches(content)) {
            final lineNumber =
                content.substring(0, m.start).split('\n').length;
            matches.add(RuleMatch(
              lineNumber: lineNumber,
              matchedText: 'Custom URL scheme registered',
            ));
          }
          return matches;
        },
        fileExtensions: ['.plist'],
      ),

      // 37. Missing ProGuard/R8
      ScanRule(
        id: 'PLT007',
        category: _cat,
        severity: Severity.high,
        title: 'Android minification/obfuscation not enabled',
        description:
            'ProGuard/R8 not enabled for release builds. Code is easily decompiled.',
        recommendation:
            'Enable minifyEnabled true and shrinkResources true in build.gradle release config.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (path.endsWith('build.gradle') || path.endsWith('build.gradle.kts')) {
            if (content.contains('release') && !content.contains('minifyEnabled true') && !content.contains('isMinifyEnabled = true')) {
              final lines = content.split('\n');
              for (var i = 0; i < lines.length; i++) {
                if (lines[i].contains('release')) {
                  matches.add(RuleMatch(
                    lineNumber: i + 1,
                    matchedText: 'Release build type without minifyEnabled',
                  ));
                  break;
                }
              }
            }
          }
          return matches;
        },
        fileExtensions: ['.gradle', '.kts'],
      ),

      // 38. Missing Dart Obfuscation
      ScanRule(
        id: 'PLT008',
        category: _cat,
        severity: Severity.high,
        title: 'Dart obfuscation not configured',
        description:
            'Build scripts missing --obfuscate --split-debug-info flags.',
        recommendation:
            'Add --obfuscate --split-debug-info=build/debug-info to release builds. '
            'Use ObfuscationShield.isObfuscated() to verify at runtime.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          // Check YAML/YML CI files and shell scripts
          final isCiYaml = (path.endsWith('.yaml') || path.endsWith('.yml')) &&
              (path.contains('.github/workflows') ||
                  path.contains('.circleci') ||
                  path.contains('ci/') ||
                  path.contains('pipeline') ||
                  path.contains('fastlane') ||
                  path.contains('Makefile') ||
                  path.contains('build') ||
                  path.contains('deploy') ||
                  path.contains('release'));
          final isShellScript = path.endsWith('.sh');
          if (!isCiYaml && !isShellScript) return matches;
          if (content.contains('flutter build') && !content.contains('--obfuscate')) {
            final lines = content.split('\n');
            for (var i = 0; i < lines.length; i++) {
              if (lines[i].contains('flutter build') && !lines[i].contains('--obfuscate')) {
                matches.add(RuleMatch(
                  lineNumber: i + 1,
                  matchedText: lines[i].trim(),
                ));
              }
            }
          }
          return matches;
        },
        fileExtensions: ['.yaml', '.yml', '.sh'],
      ),

      // 39. Minimum SDK Too Low
      ScanRule(
        id: 'PLT009',
        category: _cat,
        severity: Severity.medium,
        title: 'Android minSdkVersion too low',
        description:
            'minSdkVersion below 23 — missing security features (file-based encryption, BiometricPrompt).',
        recommendation:
            'Set minSdkVersion to 23+ (Android 6.0) for modern security APIs.',
        pattern: RegExp(
          r'minSdk(Version)?\s*[=:]\s*(1[0-9]|2[0-2])\b',
        ),
        fileExtensions: ['.gradle', '.kts'],
      ),

      // 40. Permissions Over-Request
      ScanRule(
        id: 'PLT010',
        category: _cat,
        severity: Severity.medium,
        title: 'Potentially unnecessary dangerous permission',
        description:
            'Dangerous permissions declared that may not be needed (READ_CONTACTS, READ_CALL_LOG, READ_SMS, SEND_SMS, RECORD_AUDIO, READ_PHONE_STATE).',
        recommendation:
            'Audit permissions and remove any that are not strictly required.',
        pattern: RegExp(
          r'android\.permission\.(READ_CONTACTS|READ_CALL_LOG|READ_SMS|SEND_SMS|RECORD_AUDIO|READ_PHONE_STATE|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|READ_PHONE_NUMBERS)',
        ),
        fileExtensions: ['.xml'],
      ),
    ];
