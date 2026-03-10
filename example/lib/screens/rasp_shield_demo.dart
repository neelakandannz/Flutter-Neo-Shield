import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

/// Interactive demo screen showing the RASP Shield detections
class RaspShieldDemo extends StatefulWidget {
  /// Creates the layout for the [RaspShieldDemo].
  const RaspShieldDemo({super.key});

  @override
  State<RaspShieldDemo> createState() => _RaspShieldDemoState();
}

class _RaspShieldDemoState extends State<RaspShieldDemo> {
  SecurityReport? _report;
  bool _isLoading = false;

  Future<void> _runScan() async {
    setState(() {
      _isLoading = true;
      _report = null;
    });

    final report = await RaspShield.fullSecurityScan();

    if (mounted) {
      setState(() {
        _report = report;
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text(
            'RASP Shield detects runtime threats '
            'like debuggers, root/jailbreak, and emulators.',
            style: TextStyle(fontSize: 16),
          ),
          const SizedBox(height: 24),
          ElevatedButton.icon(
            onPressed: _isLoading ? null : _runScan,
            icon: _isLoading
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.security),
            label: const Text('Run Full Security Scan'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 32),
          if (_report != null) _buildReportCard(_report!),
        ],
      ),
    );
  }

  Widget _buildReportCard(SecurityReport report) {
    return Card(
      elevation: 4,
      color: report.isSafe ? Colors.green.shade50 : Colors.red.shade50,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  report.isSafe ? Icons.check_circle : Icons.warning,
                  color: report.isSafe ? Colors.green : Colors.red,
                  size: 28,
                ),
                const SizedBox(width: 12),
                Text(
                  report.isSafe ? 'Device is Safe' : 'Threats Detected!',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: report.isSafe
                        ? Colors.green.shade800
                        : Colors.red.shade800,
                  ),
                ),
              ],
            ),
            const Divider(height: 32),
            _buildResultRow('Debugger Attached', report.debuggerDetected),
            _buildResultRow('Root / Jailbreak', report.rootDetected),
            _buildResultRow('Running on Emulator', report.emulatorDetected),
            _buildResultRow('Frida Hook', report.fridaDetected),
            _buildResultRow('Hooking Framework', report.hookDetected),
            _buildResultRow('App Tampered', report.integrityTampered),
            _buildResultRow('Developer Mode', report.developerModeDetected),
            _buildResultRow('Signature Tampered', report.signatureTampered),
            _buildResultRow('Native Debugger', report.nativeDebugDetected),
            _buildResultRow('Proxy / VPN (MITM)', report.networkThreatDetected),
          ],
        ),
      ),
    );
  }

  Widget _buildResultRow(String title, bool isDetected) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(title, style: const TextStyle(fontSize: 16)),
          Chip(
            label: Text(
              isDetected ? 'Detected' : 'Clean',
              style: TextStyle(
                color: isDetected ? Colors.white : Colors.green.shade800,
                fontWeight: FontWeight.bold,
              ),
            ),
            backgroundColor: isDetected ? Colors.red : Colors.green.shade100,
            side: BorderSide.none,
          ),
        ],
      ),
    );
  }
}
