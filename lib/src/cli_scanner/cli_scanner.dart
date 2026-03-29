/// CLI Security Scanner for flutter_neo_shield.
///
/// Usage: `dart run flutter_neo_shield:scan [options]`
///
/// Scans your Flutter project for 90+ security vulnerabilities across
/// 11 categories: hardcoded secrets, insecure network, storage, platform
/// configuration, authentication, cryptography, code injection, dependency
/// supply chain, privacy, build/release, and Flutter-specific issues.
library cli_scanner;

export 'finding.dart';
export 'reporters/ascii_reporter.dart';
export 'reporters/html_reporter.dart';
export 'reporters/json_reporter.dart';
export 'reporters/junit_reporter.dart';
export 'reporters/reporter.dart';
export 'reporters/sarif_reporter.dart';
export 'rules/rule_registry.dart';
export 'scan_result.dart';
export 'scan_rule.dart';
export 'scanner_config.dart';
export 'scanner_engine.dart';
export 'severity.dart';
