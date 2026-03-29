import 'severity.dart';

export 'severity.dart' show Severity;

/// Configuration for the CLI security scanner.
class ScannerConfig {
  /// Creates a scanner configuration.
  const ScannerConfig({
    required this.projectPath,
    this.mode = ScanMode.standard,
    this.format = OutputFormat.ascii,
    this.excludePatterns = const [],
    this.excludeRules = const [],
    this.minimumSeverity = Severity.info,
    this.ciMode = false,
    this.outputFile,
    this.configFile,
  });

  /// Path to the project to scan.
  final String projectPath;

  /// Scan mode determining which rules to apply.
  final ScanMode mode;

  /// Output format for the report.
  final OutputFormat format;

  /// File patterns to exclude from scanning.
  final List<String> excludePatterns;

  /// Rule IDs to exclude from scanning.
  final List<String> excludeRules;

  /// Minimum severity level to report.
  final Severity minimumSeverity;

  /// Whether to exit with code 1 on critical/high findings.
  final bool ciMode;

  /// Optional file path to write the report to.
  final String? outputFile;

  /// Optional custom rules config file path.
  final String? configFile;
}

/// Scan mode determining which rule categories to apply.
enum ScanMode {
  /// Secrets + network only (fast CI gate).
  quick,

  /// All categories (default).
  standard,

  /// Standard + dependency audit + compliance.
  deep,
  ;

  /// Human-readable label.
  String get label => name;

  /// Description of the scan mode.
  String get description => switch (this) {
        quick => 'Quick scan (secrets + network)',
        standard => 'Standard scan (all categories)',
        deep => 'Deep scan (standard + dependency audit + compliance)',
      };
}

/// Output format for the scan report.
enum OutputFormat {
  /// Color-coded terminal report.
  ascii,

  /// Machine-readable JSON.
  json,

  /// GitHub Advanced Security (SARIF 2.1.0).
  sarif,

  /// Shareable HTML report.
  html,

  /// CI pipeline test results (JUnit XML).
  junit,
  ;

  /// Human-readable label.
  String get label => name;

  /// File extension for this format.
  String get extension => switch (this) {
        ascii => 'txt',
        json => 'json',
        sarif => 'sarif.json',
        html => 'html',
        junit => 'xml',
      };
}
