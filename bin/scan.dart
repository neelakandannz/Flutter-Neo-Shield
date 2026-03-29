#!/usr/bin/env dart
// flutter_neo_shield CLI Security Scanner
//
// Usage:
//   dart run flutter_neo_shield:scan [options]

import 'dart:io';

import 'package:flutter_neo_shield/src/cli_scanner/cli_scanner.dart';

void main(List<String> args) {
  if (args.contains('--help') || args.contains('-h')) {
    _printHelp();
    return;
  }

  if (args.contains('--list-rules')) {
    _listRules();
    return;
  }

  final config = _parseArgs(args);
  final engine = ScannerEngine(config);

  // Print startup message for ASCII format
  if (config.format == OutputFormat.ascii) {
    stderr.writeln('Scanning ${config.projectPath}...');
    stderr.writeln('Mode: ${config.mode.description}');
    stderr.writeln('');
  }

  final result = engine.scan();
  final reporter = _getReporter(config.format);
  final output = reporter.format(result);

  if (config.outputFile != null) {
    try {
      final outFile = File(config.outputFile!);
      outFile.parent.createSync(recursive: true);
      outFile.writeAsStringSync(output);
      stderr.writeln('Report written to ${config.outputFile}');
    } catch (e) {
      stderr.writeln('Error writing report to ${config.outputFile}: $e');
      exit(2);
    }
  } else {
    stdout.writeln(output);
  }

  // CI mode: exit with non-zero if failures
  if (config.ciMode && !result.passed) {
    exit(1);
  }
}

ScannerConfig _parseArgs(List<String> args) {
  String projectPath = Directory.current.path;
  ScanMode mode = ScanMode.standard;
  OutputFormat format = OutputFormat.ascii;
  List<String> excludePatterns = [];
  List<String> excludeRules = [];
  Severity minimumSeverity = Severity.info;
  bool ciMode = false;
  String? outputFile;

  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--path':
        if (i + 1 < args.length) projectPath = args[++i];
      case '--mode':
        if (i + 1 < args.length) {
          final val = args[++i];
          mode = ScanMode.values.firstWhere(
            (m) => m.name == val,
            orElse: () => ScanMode.standard,
          );
        }
      case '--format':
        if (i + 1 < args.length) {
          final val = args[++i];
          format = OutputFormat.values.firstWhere(
            (f) => f.name == val,
            orElse: () => OutputFormat.ascii,
          );
        }
      case '--output':
        if (i + 1 < args.length) outputFile = args[++i];
      case '--exclude':
        if (i + 1 < args.length) {
          excludePatterns = args[++i].split(',').map((s) => s.trim()).toList();
        }
      case '--exclude-rules':
        if (i + 1 < args.length) {
          excludeRules = args[++i].split(',').map((s) => s.trim()).toList();
        }
      case '--min-severity':
        if (i + 1 < args.length) {
          final val = args[++i];
          minimumSeverity = Severity.values.firstWhere(
            (s) => s.name == val,
            orElse: () => Severity.info,
          );
        }
      case '--ci':
        ciMode = true;
      case '--quick':
        mode = ScanMode.quick;
      case '--deep':
        mode = ScanMode.deep;
    }
  }

  // Normalize to absolute path for consistent reporting
  projectPath = Directory(projectPath).absolute.path;

  return ScannerConfig(
    projectPath: projectPath,
    mode: mode,
    format: format,
    excludePatterns: excludePatterns,
    excludeRules: excludeRules,
    minimumSeverity: minimumSeverity,
    ciMode: ciMode,
    outputFile: outputFile,
  );
}

Reporter _getReporter(OutputFormat format) => switch (format) {
      OutputFormat.ascii => AsciiReporter(),
      OutputFormat.json => JsonReporter(),
      OutputFormat.sarif => SarifReporter(),
      OutputFormat.html => HtmlReporter(),
      OutputFormat.junit => JunitReporter(),
    };

void _listRules() {
  final rules = RuleRegistry.allRules();
  final categories = <String, List<ScanRule>>{};
  for (final r in rules) {
    categories.putIfAbsent(r.category, () => []).add(r);
  }

  stdout.writeln('');
  stdout.writeln('flutter_neo_shield Security Scanner — ${rules.length} Rules');
  stdout.writeln('═' * 60);

  for (final entry in categories.entries) {
    stdout.writeln('');
    stdout.writeln('  ${entry.key} (${entry.value.length} rules)');
    stdout.writeln('  ${'─' * 50}');
    for (final r in entry.value) {
      final sev = r.severity.label.padRight(8);
      stdout.writeln('  ${r.id}  $sev  ${r.title}');
    }
  }

  stdout.writeln('');
  stdout.writeln('Total: ${rules.length} rules across ${categories.length} categories');
  stdout.writeln('');
}

void _printHelp() {
  stdout.writeln('''

flutter_neo_shield — Security Scanner
Advanced deep analysis for Flutter projects

USAGE:
  dart run flutter_neo_shield:scan [options]

OPTIONS:
  --path <dir>           Project path (default: current directory)
  --mode <mode>          Scan mode (default: standard)
                           quick    — Secrets + network only (fast CI gate)
                           standard — All categories
                           deep     — Standard + dependency audit + compliance
  --format <format>      Output format (default: ascii)
                           ascii  — Color-coded terminal report
                           json   — Machine-readable JSON
                           sarif  — GitHub Advanced Security (SARIF 2.1.0)
                           html   — Shareable HTML report
                           junit  — CI pipeline test results (JUnit XML)
  --output <file>        Write report to file instead of stdout
  --exclude <patterns>   Comma-separated file patterns to exclude
  --exclude-rules <ids>  Comma-separated rule IDs to exclude
  --min-severity <sev>   Minimum severity: critical, high, medium, low, info
  --ci                   CI mode: exit code 1 on critical/high findings
  --quick                Shorthand for --mode quick
  --deep                 Shorthand for --mode deep
  --list-rules           List all available rules and exit
  --help                 Show this help message

EXAMPLES:
  dart run flutter_neo_shield:scan
  dart run flutter_neo_shield:scan --deep --ci
  dart run flutter_neo_shield:scan --format json --output report.json
  dart run flutter_neo_shield:scan --format sarif --output results.sarif.json
  dart run flutter_neo_shield:scan --format html --output report.html
  dart run flutter_neo_shield:scan --quick --exclude "generated,*.g.dart"
  dart run flutter_neo_shield:scan --exclude-rules "NET003,STO004"
  dart run flutter_neo_shield:scan --min-severity high --ci

SEVERITY LEVELS:
  CRITICAL — Hardcoded secrets, disabled SSL, plaintext passwords
  HIGH     — Insecure storage, missing obfuscation, weak crypto
  MEDIUM   — HTTP URLs, missing pinning, overpermissions
  LOW      — Code quality, best practice suggestions
  INFO     — Recommendations for defense-in-depth

''');
}
