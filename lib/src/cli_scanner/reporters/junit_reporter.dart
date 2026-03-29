import '../scan_result.dart';
import '../severity.dart';
import 'reporter.dart';

/// JUnit XML format reporter for CI/CD pipeline integration.
class JunitReporter extends Reporter {
  @override
  String format(ScanResult result) {
    final buf = StringBuffer();
    buf.writeln('<?xml version="1.0" encoding="UTF-8"?>');

    final failures = result.findings
        .where((f) =>
            f.severity == Severity.critical || f.severity == Severity.high)
        .length;
    final testCount = result.totalFindings > 0 ? result.totalFindings : 1;
    buf.writeln('<testsuites name="flutter_neo_shield Security Scan" '
        'tests="$testCount" '
        'failures="$failures" '
        'errors="0" '
        'time="${(result.duration.inMilliseconds / 1000).toStringAsFixed(3)}">');

    final byCategory = result.findingsByCategory;
    for (final entry in byCategory.entries) {
      final catFailures = entry.value
          .where((f) =>
              f.severity == Severity.critical || f.severity == Severity.high)
          .length;

      buf.writeln('  <testsuite name="${_esc(entry.key)}" '
          'tests="${entry.value.length}" '
          'failures="$catFailures" '
          'errors="0">');

      for (final f in entry.value) {
        buf.writeln('    <testcase name="${_esc(f.ruleId)}: ${_esc(f.title)}" '
            'classname="${_esc(f.filePath)}" '
            'time="0">');

        if (f.severity == Severity.critical || f.severity == Severity.high) {
          buf.writeln('      <failure message="${_esc(f.title)}" '
              'type="${f.severity.label}">');
          buf.writeln('File: ${_esc(f.filePath)}:${f.lineNumber}');
          buf.writeln('Match: ${_esc(f.matchedText)}');
          buf.writeln('Description: ${_esc(f.rule.description)}');
          buf.writeln('Recommendation: ${_esc(f.rule.recommendation)}');
          buf.writeln('      </failure>');
        } else if (f.severity == Severity.medium) {
          buf.writeln(
              '      <system-out>${_esc(f.rule.description)} at ${_esc(f.filePath)}:${f.lineNumber}</system-out>');
        }

        buf.writeln('    </testcase>');
      }

      buf.writeln('  </testsuite>');
    }

    // If no findings, add a passing test
    if (result.findings.isEmpty) {
      buf.writeln('  <testsuite name="Security Scan" tests="1" failures="0" errors="0">');
      buf.writeln('    <testcase name="All security checks passed" classname="flutter_neo_shield" time="0"/>');
      buf.writeln('  </testsuite>');
    }

    buf.writeln('</testsuites>');
    return buf.toString();
  }

  String _esc(String s) => s
      // Strip XML-invalid control characters (keep tab, newline, carriage return)
      .replaceAll(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F]'), '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;');
}
