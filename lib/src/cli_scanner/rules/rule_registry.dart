import '../scan_rule.dart';
import '../scanner_config.dart';
import 'auth_session_rules.dart';
import 'build_release_rules.dart';
import 'code_injection_rules.dart';
import 'crypto_rules.dart';
import 'dependency_rules.dart';
import 'flutter_specific_rules.dart';
import 'hardcoded_secrets_rules.dart';
import 'insecure_storage_rules.dart';
import 'network_config_rules.dart';
import 'platform_config_rules.dart';
import 'privacy_rules.dart';

/// Central registry of all security scanning rules.
class RuleRegistry {
  /// Returns all rules applicable for the given scan mode.
  static List<ScanRule> getRules(ScanMode mode) {
    switch (mode) {
      case ScanMode.quick:
        return [
          ...hardcodedSecretsRules(),
          ...networkConfigRules(),
        ];
      case ScanMode.standard:
        return [
          ...hardcodedSecretsRules(),
          ...networkConfigRules(),
          ...insecureStorageRules(),
          ...platformConfigRules(),
          ...authSessionRules(),
          ...cryptoRules(),
          ...codeInjectionRules(),
          ...flutterSpecificRules(),
        ];
      case ScanMode.deep:
        return [
          ...hardcodedSecretsRules(),
          ...networkConfigRules(),
          ...insecureStorageRules(),
          ...platformConfigRules(),
          ...authSessionRules(),
          ...cryptoRules(),
          ...codeInjectionRules(),
          ...dependencyRules(),
          ...privacyRules(),
          ...buildReleaseRules(),
          ...flutterSpecificRules(),
        ];
    }
  }

  /// Returns all available rules regardless of scan mode.
  static List<ScanRule> allRules() => [
        ...hardcodedSecretsRules(),
        ...networkConfigRules(),
        ...insecureStorageRules(),
        ...platformConfigRules(),
        ...authSessionRules(),
        ...cryptoRules(),
        ...codeInjectionRules(),
        ...dependencyRules(),
        ...privacyRules(),
        ...buildReleaseRules(),
        ...flutterSpecificRules(),
      ];

  /// Returns all unique category names.
  static List<String> allCategories() =>
      allRules().map((r) => r.category).toSet().toList();

  /// Total number of rules.
  static int get totalRuleCount => allRules().length;
}
