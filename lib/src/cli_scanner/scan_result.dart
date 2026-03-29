import 'finding.dart';
import 'severity.dart';

/// Aggregated results from a security scan.
class ScanResult {
  /// Creates a scan result.
  const ScanResult({
    required this.findings,
    required this.filesScanned,
    required this.duration,
    required this.scanMode,
    required this.projectPath,
  });

  /// All findings discovered during the scan.
  final List<Finding> findings;

  /// Number of files scanned.
  final int filesScanned;

  /// Total scan duration.
  final Duration duration;

  /// Scan mode used (quick, standard, deep).
  final String scanMode;

  /// Project root path that was scanned.
  final String projectPath;

  /// Total number of findings.
  int get totalFindings => findings.length;

  /// Count findings by severity level.
  int countBySeverity(Severity severity) =>
      findings.where((f) => f.severity == severity).length;

  /// Number of critical findings.
  int get criticalCount => countBySeverity(Severity.critical);

  /// Number of high findings.
  int get highCount => countBySeverity(Severity.high);

  /// Number of medium findings.
  int get mediumCount => countBySeverity(Severity.medium);

  /// Number of low findings.
  int get lowCount => countBySeverity(Severity.low);

  /// Number of info findings.
  int get infoCount => countBySeverity(Severity.info);

  /// Groups findings by category.
  Map<String, List<Finding>> get findingsByCategory {
    final map = <String, List<Finding>>{};
    for (final f in findings) {
      map.putIfAbsent(f.category, () => []).add(f);
    }
    return map;
  }

  /// Groups findings by file path.
  Map<String, List<Finding>> get findingsByFile {
    final map = <String, List<Finding>>{};
    for (final f in findings) {
      map.putIfAbsent(f.filePath, () => []).add(f);
    }
    return map;
  }

  /// Security score from 0-100.
  int get score {
    if (findings.isEmpty) return 100;
    // Weighted penalty: critical findings penalize heavily
    var penalty = 0;
    for (final f in findings) {
      penalty += switch (f.severity) {
        Severity.critical => 25,
        Severity.high => 15,
        Severity.medium => 8,
        Severity.low => 3,
        Severity.info => 1,
      };
    }
    return (100 - penalty).clamp(0, 100);
  }

  /// Letter grade (A-F) based on score.
  String get grade => switch (score) {
        >= 90 => 'A',
        >= 80 => 'B',
        >= 70 => 'C',
        >= 60 => 'D',
        _ => 'F',
      };

  /// Whether the scan passed (no critical or high issues).
  bool get passed => criticalCount == 0 && highCount == 0;

  /// Converts the result to a JSON map.
  Map<String, dynamic> toJson() => {
        'projectPath': projectPath,
        'scanMode': scanMode,
        'duration': '${duration.inMilliseconds}ms',
        'filesScanned': filesScanned,
        'score': score,
        'grade': grade,
        'passed': passed,
        'summary': {
          'total': totalFindings,
          'critical': criticalCount,
          'high': highCount,
          'medium': mediumCount,
          'low': lowCount,
          'info': infoCount,
        },
        'findings': findings.map((f) => f.toJson()).toList(),
      };
}
