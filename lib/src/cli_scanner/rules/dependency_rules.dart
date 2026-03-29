import 'dart:io';

import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Dependency & Supply Chain';

/// Rules for detecting dependency and supply chain risks.
List<ScanRule> dependencyRules() => [
      // 64. Outdated Dependencies (checked via custom logic)
      ScanRule(
        id: 'DEP001',
        category: _cat,
        severity: Severity.medium,
        title: 'Check for outdated dependencies',
        description:
            'Outdated dependencies may contain known security vulnerabilities.',
        recommendation:
            'Run "flutter pub outdated" regularly and update dependencies.',
        projectCheck: (projectRoot) {
          final matches = <RuleMatch>[];
          final lockFile = File('$projectRoot/pubspec.lock');
          if (!lockFile.existsSync()) {
            matches.add(const RuleMatch(
              lineNumber: 1,
              matchedText: 'pubspec.lock not found — run "flutter pub get"',
            ));
          }
          return matches;
        },
      ),

      // 65. Unpinned Versions
      ScanRule(
        id: 'DEP002',
        category: _cat,
        severity: Severity.low,
        title: 'Unpinned dependency version',
        description:
            'Dependency uses caret (^) or "any" version — could pull in breaking/malicious updates.',
        recommendation:
            'Pin critical dependencies to exact versions for supply chain security.',
        customCheck: (path, content) {
          if (!path.endsWith('.yaml') && !path.endsWith('.yml')) return [];
          if (path.contains('pubspec.lock')) return [];
          final matches = <RuleMatch>[];
          final lines = content.split('\n');
          final unpinnedPattern = RegExp(r'''^\s+\w+:\s*(any|\^?\s*>=)''');
          // Track whether we're in a dependencies section
          var inDepsSection = false;
          for (var i = 0; i < lines.length; i++) {
            final line = lines[i];
            final trimmed = line.trimLeft();
            // Detect section headers (no leading whitespace)
            if (trimmed.isNotEmpty && !trimmed.startsWith('#') && line == trimmed) {
              inDepsSection = trimmed.startsWith('dependencies:') ||
                  trimmed.startsWith('dev_dependencies:');
            }
            if (!inDepsSection) continue;
            if (line.contains('sdk:')) continue;
            if (unpinnedPattern.hasMatch(line)) {
              matches.add(RuleMatch(
                lineNumber: i + 1,
                matchedText: line.trim(),
              ));
            }
          }
          return matches;
        },
        fileExtensions: ['.yaml'],
      ),

      // 66. Dependency Confusion
      ScanRule(
        id: 'DEP003',
        category: _cat,
        severity: Severity.high,
        title: 'Potential dependency confusion risk',
        description:
            'Private package references without explicit hosted URL. '
            'An attacker could publish a same-named package on pub.dev.',
        recommendation:
            'Use explicit hosted URL for private packages or dependency_overrides.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (!path.endsWith('.yaml') && !path.endsWith('.yml')) {
            return matches;
          }
          final pattern = RegExp(r'hosted:\s*\n\s*name:\s');
          for (final m in pattern.allMatches(content)) {
            final lineNumber =
                content.substring(0, m.start).split('\n').length;
            matches.add(RuleMatch(
              lineNumber: lineNumber,
              matchedText: 'hosted dependency without explicit URL',
            ));
          }
          return matches;
        },
        fileExtensions: ['.yaml'],
      ),

      // 67. Lockfile Integrity
      ScanRule(
        id: 'DEP004',
        category: _cat,
        severity: Severity.medium,
        title: 'Verify lockfile is committed',
        description:
            'pubspec.lock should be committed for apps (not libraries) to ensure reproducible builds.',
        recommendation:
            'Commit pubspec.lock to version control. Use DependencyShield.verifyLockfile().',
        projectCheck: (projectRoot) {
          final matches = <RuleMatch>[];
          final gitignore = File('$projectRoot/.gitignore');
          if (gitignore.existsSync()) {
            final content = gitignore.readAsStringSync();
            if (content.contains('pubspec.lock')) {
              matches.add(const RuleMatch(
                lineNumber: 1,
                matchedText: 'pubspec.lock is in .gitignore — builds are not reproducible',
              ));
            }
          }
          return matches;
        },
      ),

      // 68. Untrusted Plugins with Native Code
      ScanRule(
        id: 'DEP005',
        category: _cat,
        severity: Severity.low,
        title: 'Plugin with native code — review carefully',
        description:
            'Flutter plugins with native code can access device APIs directly. '
            'Audit native code for security implications.',
        recommendation:
            'Review native code in untrusted plugins before using them.',
        pattern: RegExp(
          r'pluginClass:\s',
        ),
        fileExtensions: ['.yaml'],
        exclusions: [
          RegExp(r'flutter_neo_shield'),
        ],
      ),

      // 69. Git Dependencies
      ScanRule(
        id: 'DEP006',
        category: _cat,
        severity: Severity.high,
        title: 'Git dependency without commit hash pin',
        description:
            'Git dependency without pinned commit ref — vulnerable to upstream compromise.',
        recommendation:
            'Pin git dependencies to a specific commit SHA, not a branch.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (!path.endsWith('.yaml') && !path.endsWith('.yml')) {
            return matches;
          }
          final gitPattern = RegExp(r'git:\s*\n\s*url:');
          final pinPattern = RegExp(r'ref:\s*[a-f0-9]{40}');
          for (final m in gitPattern.allMatches(content)) {
            // Check if there's a pinned ref within the next 200 chars
            final endIdx = (m.end + 200).clamp(0, content.length);
            final block = content.substring(m.start, endIdx);
            if (!pinPattern.hasMatch(block)) {
              final lineNumber =
                  content.substring(0, m.start).split('\n').length;
              matches.add(RuleMatch(
                lineNumber: lineNumber,
                matchedText: 'Git dependency without pinned commit SHA',
              ));
            }
          }
          return matches;
        },
        fileExtensions: ['.yaml'],
      ),

      // 70. Dependency Overrides
      ScanRule(
        id: 'DEP007',
        category: _cat,
        severity: Severity.medium,
        title: 'dependency_overrides present',
        description:
            'dependency_overrides bypass version resolution — may hide incompatibilities or vulnerabilities.',
        recommendation:
            'Remove dependency_overrides before release. They should only be used during development.',
        pattern: RegExp(
          r'^dependency_overrides:',
          multiLine: true,
        ),
        fileExtensions: ['.yaml'],
      ),
    ];
