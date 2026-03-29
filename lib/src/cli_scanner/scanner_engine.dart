import 'dart:io';

import 'finding.dart';
import 'scan_result.dart';
import 'scan_rule.dart';
import 'scanner_config.dart';
import 'rules/rule_registry.dart';

/// Core scanning engine that traverses files and applies rules.
class ScannerEngine {
  /// Creates a scanner engine with the given configuration.
  ScannerEngine(this.config);

  /// Scanner configuration.
  final ScannerConfig config;

  /// Directories to always skip.
  static const _skipDirs = {
    '.dart_tool',
    '.pub-cache',
    '.pub',
    'build',
    '.git',
    '.idea',
    '.vscode',
    '.fvm',
    '.flutter-plugins-dependencies',
    'node_modules',
    '.gradle',
    'Pods',
    '.symlinks',
    'ephemeral',
    'Generated',
  };

  /// File extensions to scan.
  static const _scanExtensions = {
    '.dart',
    '.yaml',
    '.yml',
    '.json',
    '.xml',
    '.plist',
    '.gradle',
    '.kts',
    '.properties',
    '.env',
    '.sh',
    '.swift',
    '.kt',
    '.java',
    '.js',
    '.pem',
    '.key',
    '.txt',
  };

  /// Run the scan and return results.
  ScanResult scan() {
    final stopwatch = Stopwatch()..start();

    final rules = RuleRegistry.getRules(config.mode);
    final filteredRules = rules.where((r) {
      if (config.excludeRules.contains(r.id)) return false;
      if (r.severity.weight < config.minimumSeverity.weight) return false;
      return true;
    }).toList();

    final findings = <Finding>[];
    var filesScanned = 0;

    // Collect files to scan
    final files = _collectFiles(config.projectPath);

    // Run content-based and custom rules on each file
    for (final file in files) {
      final content = _readFileSafe(file.path);
      if (content == null) continue;

      final relativePath = _relativePath(file.path, config.projectPath);

      // Check exclude patterns
      if (_isExcluded(relativePath)) continue;

      filesScanned++;

      for (final rule in filteredRules) {
        if (rule.projectCheck != null) continue; // handled separately

        // Check file extension filter
        if (rule.fileExtensions.isNotEmpty) {
          final ext = _fileExtension(file.path);
          if (!rule.fileExtensions.contains(ext)) continue;
        }

        // Run regex pattern matching
        if (rule.pattern != null) {
          final matches = _findPatternMatches(rule, relativePath, content);
          findings.addAll(matches);
        }

        // Run custom check
        if (rule.customCheck != null) {
          final matches = rule.customCheck!(relativePath, content);
          for (final m in matches) {
            findings.add(Finding(
              rule: rule,
              filePath: m.filePath ?? relativePath,
              lineNumber: m.lineNumber,
              matchedText: m.matchedText,
            ));
          }
        }
      }
    }

    // Run project-level checks
    for (final rule in filteredRules) {
      if (rule.projectCheck != null) {
        final matches = rule.projectCheck!(config.projectPath);
        for (final m in matches) {
          findings.add(Finding(
            rule: rule,
            filePath: m.filePath ?? config.projectPath,
            lineNumber: m.lineNumber,
            matchedText: m.matchedText,
          ));
        }
      }
    }

    stopwatch.stop();

    // Sort by severity (highest first), then by file
    findings.sort((a, b) {
      final sevCmp = b.severity.weight.compareTo(a.severity.weight);
      if (sevCmp != 0) return sevCmp;
      return a.filePath.compareTo(b.filePath);
    });

    return ScanResult(
      findings: findings,
      filesScanned: filesScanned,
      duration: stopwatch.elapsed,
      scanMode: config.mode.label,
      projectPath: config.projectPath,
    );
  }

  List<Finding> _findPatternMatches(
      ScanRule rule, String filePath, String content) {
    final findings = <Finding>[];
    final lines = content.split('\n');

    // Check if pattern contains constructs that can span newlines
    final patternStr = rule.pattern!.pattern;
    final isMultiline = patternStr.contains(r'[\s\S]') ||
        patternStr.contains(r'[\S\s]') ||
        patternStr.contains(r'\n');

    if (isMultiline) {
      // Match against full content for multiline patterns
      final matches = rule.pattern!.allMatches(content);
      for (final match in matches) {
        final matchedText = match.group(0) ?? '';
        // Calculate line number from match start offset
        final lineNumber =
            content.substring(0, match.start).split('\n').length;
        final contextLine =
            lineNumber <= lines.length ? lines[lineNumber - 1].trim() : '';

        // Check exclusions against surrounding context
        var excluded = false;
        // Get a window of lines around the match for exclusion checking
        final matchEnd = content.substring(0, match.end).split('\n').length;
        final startLine = (lineNumber - 1).clamp(0, lines.length - 1);
        final endLine = matchEnd.clamp(0, lines.length);
        final contextWindow =
            lines.sublist(startLine, endLine).join('\n');
        for (final exclusion in rule.exclusions) {
          if (exclusion.hasMatch(contextWindow) ||
              exclusion.hasMatch(filePath)) {
            excluded = true;
            break;
          }
        }
        if (excluded) continue;

        if (_isLikelyExample(contextLine, matchedText)) continue;

        findings.add(Finding(
          rule: rule,
          filePath: filePath,
          lineNumber: lineNumber,
          matchedText: _truncate(matchedText, 200),
          contextLine: _truncate(contextLine, 150),
        ));
      }
    } else {
      // Standard per-line matching
      for (var i = 0; i < lines.length; i++) {
        final line = lines[i];
        final matches = rule.pattern!.allMatches(line);

        for (final match in matches) {
          final matchedText = match.group(0) ?? '';

          // Check exclusions
          var excluded = false;
          for (final exclusion in rule.exclusions) {
            if (exclusion.hasMatch(line) || exclusion.hasMatch(filePath)) {
              excluded = true;
              break;
            }
          }
          if (excluded) continue;

          // Skip if it looks like a comment with example/placeholder
          if (_isLikelyExample(line, matchedText)) continue;

          findings.add(Finding(
            rule: rule,
            filePath: filePath,
            lineNumber: i + 1,
            matchedText: _truncate(matchedText, 200),
            contextLine: _truncate(line.trim(), 150),
          ));
        }
      }
    }

    return findings;
  }

  bool _isLikelyExample(String line, String match) {
    final lowerMatch = match.toLowerCase();
    // Only suppress if the matched value itself looks like a placeholder
    if (lowerMatch.contains('example') ||
        lowerMatch.contains('placeholder') ||
        lowerMatch.contains('your-') ||
        lowerMatch.contains('your_') ||
        lowerMatch.contains('xxx') ||
        lowerMatch.contains('change-me') ||
        lowerMatch.contains('insert-') ||
        lowerMatch.contains('replace-')) {
      return true;
    }
    // Also suppress if entire line is a comment with placeholder indicators
    final trimmed = line.trimLeft();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
      final lower = trimmed.toLowerCase();
      if (lower.contains('example') ||
          lower.contains('placeholder') ||
          lower.contains('todo:') ||
          lower.contains('fixme:')) {
        return true;
      }
    }
    return false;
  }

  List<File> _collectFiles(String root) {
    final dir = Directory(root);
    if (!dir.existsSync()) return [];

    final files = <File>[];
    _walkDirectory(dir, files);
    return files;
  }

  void _walkDirectory(Directory dir, List<File> files) {
    try {
      final entities = dir.listSync(followLinks: false);
      for (final entity in entities) {
        if (entity is Directory) {
          final name = entity.path.split(Platform.pathSeparator).last;
          // Allow .github and .circleci; skip other dot-dirs
          if (!_skipDirs.contains(name) &&
              !(name.startsWith('.') &&
                  name != '.github' &&
                  name != '.circleci')) {
            _walkDirectory(entity, files);
          }
        } else if (entity is File) {
          final ext = _fileExtension(entity.path);
          if (_scanExtensions.contains(ext)) {
            files.add(entity);
          }
        }
      }
    } catch (_) {
      // Permission denied, broken symlink, etc. — skip silently
    }
  }

  String? _readFileSafe(String path) {
    try {
      final file = File(path);
      // Skip very large files (>1MB) — likely generated/binary
      if (file.lengthSync() > 1024 * 1024) return null;
      return file.readAsStringSync();
    } catch (_) {
      return null;
    }
  }

  String _relativePath(String fullPath, String root) {
    if (fullPath.startsWith(root)) {
      var rel = fullPath.substring(root.length);
      if (rel.startsWith(Platform.pathSeparator)) {
        rel = rel.substring(1);
      }
      return rel;
    }
    return fullPath;
  }

  String _fileExtension(String path) {
    final separator = path.lastIndexOf(Platform.pathSeparator);
    final filename = separator >= 0 ? path.substring(separator + 1) : path;
    final dot = filename.lastIndexOf('.');
    return dot >= 0 ? filename.substring(dot) : '';
  }

  bool _isExcluded(String path) {
    for (final pattern in config.excludePatterns) {
      if (pattern.contains('*') || pattern.contains('?')) {
        // Convert glob to regex: escape special chars, convert * and ?
        final regexStr = pattern
            .replaceAll(r'\', r'\\')
            .replaceAll('.', r'\.')
            .replaceAll('(', r'\(')
            .replaceAll(')', r'\)')
            .replaceAll('[', r'\[')
            .replaceAll(']', r'\]')
            .replaceAll('*', '.*')
            .replaceAll('?', '.');
        // Anchor to match full path segments
        if (RegExp('^$regexStr\$').hasMatch(path) ||
            RegExp('(^|/)$regexStr\$').hasMatch(path)) {
          return true;
        }
      } else {
        if (path.contains(pattern)) return true;
      }
    }
    return false;
  }

  String _truncate(String s, int maxLen) =>
      s.length <= maxLen ? s : '${s.substring(0, maxLen - 3)}...';
}
