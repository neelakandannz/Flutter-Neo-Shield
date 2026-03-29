import 'scan_rule.dart';
import 'severity.dart';

/// A single security finding discovered during scanning.
class Finding {
  /// Creates a finding.
  const Finding({
    required this.rule,
    required this.filePath,
    required this.lineNumber,
    required this.matchedText,
    this.contextLine,
  });

  /// The rule that triggered this finding.
  final ScanRule rule;

  /// Path to the file containing the finding.
  final String filePath;

  /// Line number of the finding.
  final int lineNumber;

  /// The text that matched the rule.
  final String matchedText;

  /// The full context line from the source.
  final String? contextLine;

  /// Severity of this finding.
  Severity get severity => rule.severity;

  /// Rule ID that triggered this finding.
  String get ruleId => rule.id;

  /// Category of this finding.
  String get category => rule.category;

  /// Short title of this finding.
  String get title => rule.title;

  /// Converts this finding to a JSON map.
  Map<String, dynamic> toJson() => {
        'ruleId': ruleId,
        'category': category,
        'severity': severity.name,
        'title': title,
        'description': rule.description,
        'recommendation': rule.recommendation,
        'file': filePath,
        'line': lineNumber,
        'match': matchedText,
        if (contextLine != null) 'context': contextLine,
      };

  @override
  String toString() => '${severity.icon} $filePath:$lineNumber — $title';
}
