import Foundation
import Darwin
import MachO

// ptrace is not directly available in Swift; we declare it from C
// PT_DENY_ATTACH = 31
@_silgen_name("ptrace")
private func swift_ptrace(_ request: CInt, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: CInt) -> CInt

/// Native-level debugger detection for iOS.
///
/// The existing DebuggerDetector checks P_TRACED via sysctl (one-time).
/// This detector adds:
///
/// 1. PT_DENY_ATTACH — prevents debugger attachment entirely.
/// 2. Repeated sysctl check — catches debuggers attaching after the first check.
/// 3. Exception port check — debuggers register Mach exception ports.
/// 4. Timing-based detection — single-stepping causes measurable delays.
///
/// Kept in a separate file to avoid modifying DebuggerDetector.swift.
public class NativeDebugDetector {

    /// Runs all native-level debug detection checks.
    /// Returns true if native debugging is detected.
    public static func check() -> Bool {
        return checkSysctl() ||
               checkExceptionPorts() ||
               checkTimingAnomaly()
    }

    /// Calls PT_DENY_ATTACH to prevent future debugger attachment.
    ///
    /// This is a one-way operation: once called, any attempt to attach
    /// a debugger (lldb, gdb) will fail. The debugger gets SEGFAULT.
    ///
    /// Call this early in app startup for maximum protection.
    /// Returns true if the call succeeded.
    public static func denyDebuggerAttachment() -> Bool {
        let PT_DENY_ATTACH: CInt = 31
        let result = swift_ptrace(PT_DENY_ATTACH, 0, nil, 0)
        return result == 0
    }

    /// Checks P_TRACED flag via sysctl.
    ///
    /// Same mechanism as DebuggerDetector but included here so
    /// NativeDebugDetector is self-contained.
    private static func checkSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return false
        }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Checks for debugger via Mach exception ports.
    ///
    /// When a debugger attaches, it registers exception ports to receive
    /// signals (breakpoints, crashes). We check if any non-standard
    /// exception ports are registered on the current task.
    private static func checkExceptionPorts() -> Bool {
        var count: mach_msg_type_number_t = 0
        let excTypesCount = Int(EXC_TYPES_COUNT)
        var masks = [exception_mask_t](repeating: 0, count: excTypesCount)
        var ports = [mach_port_t](repeating: 0, count: excTypesCount)
        var behaviors = [exception_behavior_t](repeating: 0, count: excTypesCount)
        var flavors = [thread_state_flavor_t](repeating: 0, count: excTypesCount)

        // EXC_MASK_ALL = mask covering all exception types
        let excMaskAll: exception_mask_t = exception_mask_t(
            EXC_MASK_BAD_ACCESS |
            EXC_MASK_BAD_INSTRUCTION |
            EXC_MASK_ARITHMETIC |
            EXC_MASK_EMULATION |
            EXC_MASK_SOFTWARE |
            EXC_MASK_BREAKPOINT |
            EXC_MASK_SYSCALL |
            EXC_MASK_MACH_SYSCALL |
            EXC_MASK_RPC_ALERT |
            EXC_MASK_MACHINE
        )

        let result = withUnsafeMutablePointer(to: &count) { countPtr in
            task_get_exception_ports(
                mach_task_self_,
                excMaskAll,
                &masks,
                countPtr,
                &ports,
                &behaviors,
                &flavors
            )
        }

        if result != KERN_SUCCESS {
            return false
        }

        // If any exception port is set (non-null), a debugger may be attached
        for i in 0..<Int(count) {
            if ports[i] != 0 && ports[i] != mach_port_t(MACH_PORT_NULL) {
                return true
            }
        }

        return false
    }

    /// Timing-based detection: debugger single-stepping causes delays.
    ///
    /// A tight loop that normally runs in < 5ms will take much longer
    /// when a debugger is single-stepping through the code.
    private static func checkTimingAnomaly() -> Bool {
        let start = CFAbsoluteTimeGetCurrent()
        var sum: Int64 = 0
        for i in 0..<10000 {
            sum += Int64(i)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start
        _ = sum // Prevent optimizer from removing the loop

        // 500ms threshold — normal execution < 5ms even on older devices
        return elapsed > 0.5
    }
}
