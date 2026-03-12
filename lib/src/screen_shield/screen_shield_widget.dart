import 'dart:async';
import 'package:flutter/widgets.dart';

import 'screen_shield.dart';
import 'screen_shield_callback.dart';

/// A widget that enables screen protection for its subtree.
///
/// When this widget is mounted, screen protection is enabled.
/// When disposed, protection is disabled (unless [disableOnDispose]
/// is set to false).
///
/// ```dart
/// ScreenShieldScope(
///   onScreenshot: () => print('Screenshot attempted!'),
///   child: Scaffold(
///     body: SensitiveContent(),
///   ),
/// )
/// ```
class ScreenShieldScope extends StatefulWidget {
  /// Creates a [ScreenShieldScope] that protects its [child].
  const ScreenShieldScope({
    super.key,
    required this.child,
    this.enableProtection = true,
    this.guardAppSwitcher = true,
    this.disableOnDispose = true,
    this.onScreenshot,
    this.onRecordingStateChanged,
  });

  /// The child widget to protect.
  final Widget child;

  /// Whether to enable screen protection.
  final bool enableProtection;

  /// Whether to enable the app switcher guard.
  final bool guardAppSwitcher;

  /// Whether to disable protection when this widget is disposed.
  ///
  /// Set to false if protection should persist across navigation.
  final bool disableOnDispose;

  /// Called when a screenshot is detected (iOS only).
  final VoidCallback? onScreenshot;

  /// Called when screen recording state changes.
  final ValueChanged<bool>? onRecordingStateChanged;

  @override
  State<ScreenShieldScope> createState() => _ScreenShieldScopeState();
}

class _ScreenShieldScopeState extends State<ScreenShieldScope> {
  final _shield = ScreenShield();
  StreamSubscription<ScreenshotEvent>? _screenshotSub;
  StreamSubscription<RecordingStateEvent>? _recordingSub;

  /// Monotonically increasing counter to detect stale async operations.
  /// When a newer [_applyProtection] call starts, it increments the epoch
  /// so that the previous in-flight call can detect it has been superseded.
  int _protectionEpoch = 0;

  @override
  void initState() {
    super.initState();
    _applyProtection();
    _subscribeToEvents();
  }

  @override
  void didUpdateWidget(ScreenShieldScope oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.enableProtection != widget.enableProtection ||
        oldWidget.guardAppSwitcher != widget.guardAppSwitcher) {
      _applyProtection();
    }
    if (oldWidget.onScreenshot != widget.onScreenshot ||
        oldWidget.onRecordingStateChanged != widget.onRecordingStateChanged) {
      _subscribeToEvents();
    }
  }

  Future<void> _applyProtection() async {
    final epoch = ++_protectionEpoch;

    if (widget.enableProtection) {
      await _shield.enableProtection();
    } else {
      await _shield.disableProtection();
    }

    // A newer call has superseded this one — stop here.
    if (epoch != _protectionEpoch) return;

    if (widget.guardAppSwitcher) {
      await _shield.enableAppSwitcherGuard();
    } else {
      await _shield.disableAppSwitcherGuard();
    }
  }

  void _subscribeToEvents() {
    _screenshotSub?.cancel();
    _recordingSub?.cancel();

    if (widget.onScreenshot != null) {
      _screenshotSub = _shield.onScreenshotDetected.listen((_) {
        widget.onScreenshot?.call();
      });
    }

    if (widget.onRecordingStateChanged != null) {
      _recordingSub = _shield.onRecordingStateChanged.listen((event) {
        widget.onRecordingStateChanged?.call(event.isRecording);
      });
    }
  }

  @override
  void dispose() {
    _screenshotSub?.cancel();
    _recordingSub?.cancel();
    if (widget.disableOnDispose) {
      unawaited(_shield.disableProtection());
      unawaited(_shield.disableAppSwitcherGuard());
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
