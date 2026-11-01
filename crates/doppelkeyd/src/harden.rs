//! Process hardening for the keeper. See docs/research.md: on Linux PR_SET_DUMPABLE=0 alone
//! stops same-user processes from reading /proc/<pid>/mem and environ or attaching ptrace.

/// Environment variables that would let another program inject code into the keeper.
const INJECTION_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
];

/// Returns the names of injection variables present (the keeper refuses to start with any).
pub fn injection_vars() -> Vec<&'static str> {
    INJECTION_VARS
        .iter()
        .copied()
        .filter(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
        .collect()
}

/// Apply hardening. Returns notes on what could not be applied (never fatal).
pub fn apply() -> Vec<String> {
    let mut notes = Vec::new();
    unsafe {
        libc::umask(0o077);
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            notes.push("could not disable core dumps".into());
        }
        #[cfg(target_os = "linux")]
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            notes.push("could not set PR_SET_DUMPABLE=0".into());
        }
        #[cfg(target_os = "macos")]
        {
            // PT_DENY_ATTACH: blocks ptrace/dtrace attach. task_for_pid is gated by code signing
            // (hardened runtime, no get-task-allow); see docs/research.md.
            const PT_DENY_ATTACH: libc::c_int = 31;
            if libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) != 0 {
                notes.push("could not set PT_DENY_ATTACH".into());
            }
        }
    }
    notes
}

/// Is this process protected from same-user memory reads? (Linux: dumpable flag is 0.)
pub fn is_non_dumpable() -> Option<bool> {
    #[cfg(target_os = "linux")]
    unsafe {
        return Some(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
    }
    #[allow(unreachable_code)]
    None
}
