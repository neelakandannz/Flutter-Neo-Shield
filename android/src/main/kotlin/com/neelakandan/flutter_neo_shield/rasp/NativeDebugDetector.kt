package com.neelakandan.flutter_neo_shield.rasp

import java.io.File

/**
 * Native-level debugger detection that catches GDB, LLDB, and other
 * native debuggers attached from desktop via ADB.
 *
 * The existing DebuggerDetector only checks Java-level debugging
 * (Debug.isDebuggerConnected). This detector checks:
 *
 * 1. /proc/self/status TracerPid — non-zero means a native debugger
 *    (GDB, LLDB, strace) is ptrace-attached to this process.
 * 2. /proc/self/wchan — if the process is stopped in ptrace_stop.
 * 3. Timing-based detection — single-stepping causes measurable delays.
 */
class NativeDebugDetector {

    fun check(): Boolean {
        return checkTracerPid() || checkWchan() || checkTimingAnomaly()
    }

    /**
     * Reads /proc/self/status and checks TracerPid.
     * TracerPid != 0 means a process is ptrace-attached (native debugger).
     */
    private fun checkTracerPid(): Boolean {
        try {
            val statusFile = File("/proc/self/status")
            if (!statusFile.exists()) return false

            val lines = statusFile.readLines()
            for (line in lines) {
                if (line.startsWith("TracerPid:")) {
                    val pid = line.substringAfter("TracerPid:").trim()
                    if (pid != "0") {
                        return true // A process is tracing us
                    }
                }
            }
        } catch (e: Exception) {
            // If we can't read /proc, don't flag
        }
        return false
    }

    /**
     * Checks /proc/self/wchan for ptrace_stop.
     * When a debugger halts execution, the wait channel shows ptrace_stop.
     */
    private fun checkWchan(): Boolean {
        try {
            val wchanFile = File("/proc/self/wchan")
            if (!wchanFile.exists()) return false

            val wchan = wchanFile.readText().trim()
            if (wchan.contains("ptrace_stop") || wchan.contains("trace")) {
                return true
            }
        } catch (e: Exception) {
            // Ignore
        }
        return false
    }

    /**
     * Timing-based detection: when single-stepping through code with a
     * debugger, even simple operations take much longer than normal.
     *
     * We measure the time for a tight loop. Under normal execution this
     * takes < 5ms. Under a debugger with breakpoints or single-stepping,
     * it takes significantly longer.
     *
     * Threshold is set conservatively to avoid false positives on slow devices.
     */
    private fun checkTimingAnomaly(): Boolean {
        try {
            val start = System.nanoTime()
            // Simple computation that should be very fast
            @Suppress("UNUSED_VARIABLE")
            var sum = 0L
            for (i in 0 until 10000) {
                sum += i
            }
            val elapsed = System.nanoTime() - start

            // 500ms threshold — normal execution is < 5ms even on slow devices.
            // A debugger single-stepping would take seconds.
            if (elapsed > 500_000_000L) {
                return true
            }
        } catch (e: Exception) {
            // Ignore
        }
        return false
    }
}
