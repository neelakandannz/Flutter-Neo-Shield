/// Severity levels for security scan findings.
enum Severity {
  /// Hardcoded secrets, disabled SSL, plaintext passwords.
  critical,

  /// Insecure storage, missing obfuscation, weak crypto.
  high,

  /// HTTP URLs, missing pinning, overpermissions.
  medium,

  /// Code quality, best practice suggestions.
  low,

  /// Recommendations for defense-in-depth.
  info;

  /// Human-readable uppercase label.
  String get label => name.toUpperCase();

  /// ANSI escape code for terminal coloring.
  String get ansiColor => switch (this) {
        critical => '\x1B[91m',
        high => '\x1B[31m',
        medium => '\x1B[33m',
        low => '\x1B[36m',
        info => '\x1B[37m',
      };

  /// Severity indicator for terminal output.
  String get icon => switch (this) {
        critical => '[!!!]',
        high => '[!!]',
        medium => '[!]',
        low => '[~]',
        info => '[i]',
      };

  /// Numeric weight for scoring.
  int get weight => switch (this) {
        critical => 5,
        high => 4,
        medium => 3,
        low => 2,
        info => 1,
      };
}
