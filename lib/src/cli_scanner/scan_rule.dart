import 'severity.dart';

/// Defines a single security scanning rule.
class ScanRule {
  /// Creates a scan rule.
  const ScanRule({
    required this.id,
    required this.category,
    required this.severity,
    required this.title,
    required this.description,
    required this.recommendation,
    this.pattern,
    this.fileExtensions = const [],
    this.exclusions = const [],
    this.customCheck,
    this.projectCheck,
  });

  /// Unique rule identifier (e.g., SEC001).
  final String id;

  /// Category name (e.g., "Hardcoded Secrets").
  final String category;

  /// Severity level of the finding.
  final Severity severity;

  /// Short title describing the issue.
  final String title;

  /// Detailed description of the security risk.
  final String description;

  /// How to fix the issue.
  final String recommendation;

  /// Regex pattern for content-based scanning.
  final RegExp? pattern;

  /// File extensions this rule applies to. Empty means all files.
  final List<String> fileExtensions;

  /// Patterns that indicate a false positive.
  final List<RegExp> exclusions;

  /// Custom check function for complex logic beyond regex.
  final List<RuleMatch> Function(String path, String content)? customCheck;

  /// Project-level check (file existence, config analysis).
  final List<RuleMatch> Function(String projectRoot)? projectCheck;
}

/// A match found by a rule within a file.
class RuleMatch {
  /// Creates a rule match.
  const RuleMatch({
    required this.lineNumber,
    required this.matchedText,
    this.filePath,
  });

  /// Line number where the match was found.
  final int lineNumber;

  /// The matched text content.
  final String matchedText;

  /// Optional file path override.
  final String? filePath;
}
