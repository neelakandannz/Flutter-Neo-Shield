import '../scan_result.dart';

/// Base class for scan result reporters.
abstract class Reporter {
  /// Formats the scan result into a string output.
  String format(ScanResult result);
}
