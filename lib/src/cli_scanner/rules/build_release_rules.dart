import 'dart:io';

import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Build & Release Security';

/// Rules for detecting build and release security issues.
List<ScanRule> buildReleaseRules() => [
      // 78. Debug Symbols in Release
      ScanRule(
        id: 'BLD001',
        category: _cat,
        severity: Severity.medium,
        title: 'Debug symbols may be bundled',
        description:
            'Debug symbols (.dSYM, mapping files) may be included in release builds.',
        recommendation:
            'Use --split-debug-info to separate debug symbols from release binary.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (path.endsWith('build.gradle') || path.endsWith('build.gradle.kts')) {
            if (content.contains('release') &&
                (!content.contains('ndk') || !content.contains('strip')) &&
                !content.contains('split-debug-info') &&
                !content.contains('splitDebugInfo')) {
              final lines = content.split('\n');
              for (var i = 0; i < lines.length; i++) {
                if (lines[i].contains('release')) {
                  matches.add(RuleMatch(
                    lineNumber: i + 1,
                    matchedText:
                        'Release build without debug symbol stripping',
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

      // 79. Source Maps Exposed
      ScanRule(
        id: 'BLD002',
        category: _cat,
        severity: Severity.high,
        title: 'Web source maps may be deployed',
        description:
            'Source maps expose original Dart code in web builds. Should not be in production.',
        recommendation:
            'Exclude .js.map files from production web deployment. Add to .gitignore.',
        projectCheck: (projectRoot) {
          final matches = <RuleMatch>[];
          final webBuild = Directory('$projectRoot/build/web');
          if (webBuild.existsSync()) {
            final mapFiles = webBuild
                .listSync(recursive: true)
                .whereType<File>()
                .where((f) => f.path.endsWith('.js.map'));
            for (final f in mapFiles) {
              matches.add(RuleMatch(
                lineNumber: 1,
                matchedText: 'Source map found: ${f.path}',
                filePath: f.path,
              ));
            }
          }
          return matches;
        },
      ),

      // 80. Environment Files Committed
      ScanRule(
        id: 'BLD003',
        category: _cat,
        severity: Severity.critical,
        title: 'Environment file in project',
        description:
            '.env file found in project — may contain secrets that get committed to git.',
        recommendation:
            'Add .env* to .gitignore. Use --dart-define or platform-specific config.',
        projectCheck: (projectRoot) {
          final matches = <RuleMatch>[];
          final envFiles = ['.env', '.env.local', '.env.production', '.env.staging'];
          for (final name in envFiles) {
            final f = File('$projectRoot/$name');
            if (f.existsSync()) {
              matches.add(RuleMatch(
                lineNumber: 1,
                matchedText: '$name file exists in project root',
                filePath: f.path,
              ));
            }
          }

          // Check .gitignore for .env exclusion
          final gitignore = File('$projectRoot/.gitignore');
          if (gitignore.existsSync()) {
            final content = gitignore.readAsStringSync();
            if (!content.contains('.env')) {
              matches.add(const RuleMatch(
                lineNumber: 1,
                matchedText: '.env not in .gitignore — secrets may be committed',
              ));
            }
          }
          return matches;
        },
      ),

      // 81. Signing Config Hardcoded
      ScanRule(
        id: 'BLD004',
        category: _cat,
        severity: Severity.critical,
        title: 'Keystore password hardcoded in build.gradle',
        description:
            'Signing credentials hardcoded in build files — visible in version control.',
        recommendation:
            'Load signing config from environment variables or local.properties (gitignored).',
        pattern: RegExp(
          r"""(storePassword|keyPassword|keyAlias)\s*[=:]\s*['"][^'"]+['"]""",
        ),
        fileExtensions: ['.gradle', '.kts', '.properties'],
        exclusions: [
          RegExp(r'local\.properties'),
          RegExp(r'System\.getenv'),
          RegExp(r'project\.property'),
        ],
      ),

      // 82. Test Code in Release
      ScanRule(
        id: 'BLD005',
        category: _cat,
        severity: Severity.medium,
        title: 'Test utility imported in production code',
        description:
            'Test packages (mocktail, mockito, fake_async, flutter_test) imported in lib/ code.',
        recommendation:
            'Move test imports to test/ directory only.',
        pattern: RegExp(
          r'''import\s+['"]package:(mocktail|mockito|fake_async|flutter_test|test)/''',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'_test\.dart$'),
          RegExp(r'test/'),
          RegExp(r'test\\'),
        ],
      ),

      // 83. Dev Dependencies in Lib
      ScanRule(
        id: 'BLD006',
        category: _cat,
        severity: Severity.medium,
        title: 'Dev-only package imported in lib/',
        description:
            'Packages from dev_dependencies imported in lib/ code — will fail for consumers.',
        recommendation:
            'Move dev-only imports to test/ or move the package to dependencies.',
        pattern: RegExp(
          r'''import\s+['"]package:(build_runner|build_test|lints|flutter_lints|very_good_analysis)/''',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'_test\.dart$'),
          RegExp(r'test/'),
          RegExp(r'test\\'),
        ],
      ),
    ];
