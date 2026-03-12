package com.neelakandan.flutter_neo_shield.rasp

import java.io.File
import java.net.Socket
import java.util.Scanner

class FridaDetector {
    fun check(): Boolean {
        // 1. Check for Frida on common ports
        val fridaPorts = intArrayOf(27042, 27043, 4444)
        for (port in fridaPorts) {
            try {
                Socket("127.0.0.1", port).use {
                    return true
                }
            } catch (e: Exception) {
                // port not open
            }
        }

        // 2. Scan memory maps for frida agent
        try {
            val pid = android.os.Process.myPid()
            val file = File("/proc/$pid/maps")
            if (file.exists()) {
                Scanner(file).use { scanner ->
                    while (scanner.hasNextLine()) {
                        val line = scanner.nextLine()
                        if (line.contains("frida-agent") ||
                            line.contains("frida-gadget") ||
                            line.contains("frida-server") ||
                            line.contains("linjector")) {
                            return true
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore unable to read /proc/...
        }

        return false
    }
}
