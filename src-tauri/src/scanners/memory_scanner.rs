use crate::data::suspicious_flags::{CRITICAL_FLAGS, HIGH_FLAGS, MEDIUM_FLAGS, get_flag_category, get_flag_description};
use crate::models::{ScanFinding, ScanVerdict};
use std::collections::HashSet;

/// Known FFlag prefixes to search for in memory.
#[allow(dead_code)]
const FFLAG_PREFIXES: &[&str] = &[
    "DFInt",
    "DFFlag",
    "FFlagDebug",
    "FIntDebug",
    "DFFlagDebug",
    "FFlagSim",
    "DFIntS2",
    "DFIntReplicator",
    "DFIntAssembly",
    "FIntRender",
    "FFlagGlobal",
    "DFIntTask",
    "FFlagAd",
    "FFlagFast",
    "FIntFullscreen",
];

/// Hard cap on regions walked per scan, to prevent runaway loops when an OS
/// enumeration API misbehaves. Roblox typically has far fewer regions than this.
const MAX_REGIONS_WALKED: usize = 200_000;

/// Max per-region read (16 MiB). Regions larger than this are skipped for string search
/// but still counted and walked past.
const MAX_REGION_READ_BYTES: usize = 16 * 1024 * 1024;

/// All suspicious flag names combined for memory search.
fn all_suspicious_flags() -> Vec<&'static str> {
    let mut flags: Vec<&'static str> = Vec::new();
    flags.extend_from_slice(CRITICAL_FLAGS);
    flags.extend_from_slice(HIGH_FLAGS);
    flags.extend_from_slice(MEDIUM_FLAGS);
    flags
}

/// Per-scan state for deduplicating findings across regions.
#[derive(Default)]
struct FlagHitTracker {
    seen: HashSet<&'static str>,
}

impl FlagHitTracker {
    fn record(&mut self, flag: &'static str) -> bool {
        self.seen.insert(flag)
    }
    fn total(&self) -> usize {
        self.seen.len()
    }
}

/// Scan Roblox process memory for runtime FFlag injections.
pub async fn scan() -> Vec<ScanFinding> {
    #[cfg(target_os = "windows")]
    {
        scan_windows().await
    }

    #[cfg(target_os = "macos")]
    {
        scan_macos().await
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        vec![ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Suspicious,
            "Memory scan unavailable: unsupported platform",
            None,
        )]
    }
}

/// Result of locating a Roblox process: the PID and whether the executable
/// path passed basic validation against expected Roblox install roots.
struct RobloxProcess {
    pid: u32,
    exe_path: Option<String>,
    path_looks_trusted: bool,
}

/// Find the Roblox process PID, validating the executable path against
/// expected install roots. Falls back to name-only matching when the path
/// cannot be read.
fn find_roblox_process() -> Option<RobloxProcess> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys = System::new_with_specifics(RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()));
    sys.refresh_all();

    #[cfg(target_os = "windows")]
    let name_hint = "robloxplayerbeta";
    #[cfg(target_os = "macos")]
    let name_hint = "robloxplayer";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let name_hint = "roblox";

    let mut best: Option<RobloxProcess> = None;

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        if !name.contains(name_hint) {
            continue;
        }
        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string());
        let path_looks_trusted = exe_path
            .as_deref()
            .map(is_trusted_roblox_exe_path)
            .unwrap_or(false);

        let candidate = RobloxProcess {
            pid: pid.as_u32(),
            exe_path,
            path_looks_trusted,
        };

        // Prefer a trusted-path match; otherwise keep the first name match.
        match &best {
            Some(b) if b.path_looks_trusted => {}
            _ => best = Some(candidate),
        }
        if let Some(b) = &best {
            if b.path_looks_trusted {
                break;
            }
        }
    }

    best
}

/// Check whether an executable path looks like a real Roblox install.
fn is_trusted_roblox_exe_path(exe_path: &str) -> bool {
    let lower = exe_path.to_lowercase();
    #[cfg(target_os = "windows")]
    {
        let roots: Vec<String> = trusted_windows_roblox_roots();
        roots.iter().any(|r| lower.starts_with(&r.to_lowercase()))
    }
    #[cfg(target_os = "macos")]
    {
        lower.starts_with("/applications/roblox.app/")
            || lower.contains("/roblox.app/contents/macos/")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        false
    }
}

/// Search a memory buffer for suspicious FFlag strings.
/// Uses per-scan dedup so the same flag name appearing in multiple regions
/// is reported only once per scan.
fn search_buffer_for_flags(
    buffer: &[u8],
    base_address: usize,
    flags: &[&'static str],
    tracker: &mut FlagHitTracker,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for &flag_name in flags {
        // Skip empty entries defensively (shouldn't happen in the static tables).
        if flag_name.is_empty() {
            continue;
        }
        // Already reported this scan — skip the scan entirely for this flag.
        if tracker.seen.contains(flag_name) {
            continue;
        }
        let flag_bytes = flag_name.as_bytes();
        if flag_bytes.len() > buffer.len() {
            continue;
        }

        let end = buffer.len() - flag_bytes.len();
        let mut i = 0usize;
        while i <= end {
            if &buffer[i..i + flag_bytes.len()] == flag_bytes
                && is_contextual_flag_match(buffer, i, flag_bytes.len())
            {
                if !tracker.record(flag_name) {
                    break;
                }
                let severity = crate::data::suspicious_flags::get_flag_severity(flag_name);
                let address = base_address.saturating_add(i);
                let category = get_flag_category(flag_name).unwrap_or("UNKNOWN");
                let desc = get_flag_description(flag_name);
                let detail_suffix = desc.map(|d| format!(" | {}", d)).unwrap_or_default();

                findings.push(ScanFinding::new(
                    "memory_scanner",
                    severity,
                    format!("FFlag found in Roblox memory: \"{}\"", flag_name),
                    Some(format!(
                        "Address: 0x{:X} | Category: {}{}",
                        address, category, detail_suffix
                    )),
                ));
                break;
            }
            i += 1;
        }
    }

    findings
}

/// Require that the match be bounded by non-identifier bytes (or start/end of buffer)
/// and that at least one surrounding byte resembles a key/value delimiter
/// (`"`, `:`, `=`, `{`, `,`, NUL). This filters out matches inside longer
/// identifiers (FFlagFooBar matching FFlagFoo) and most natural-language prose,
/// while still catching both JSON-style `"FFlagFoo":true` and NUL-terminated
/// C-string forms.
fn is_contextual_flag_match(buffer: &[u8], start: usize, len: usize) -> bool {
    let before = if start == 0 { None } else { Some(buffer[start - 1]) };
    let after_idx = start + len;
    let after = if after_idx < buffer.len() { Some(buffer[after_idx]) } else { None };

    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // Reject if immediately adjacent to another identifier byte — that means
    // this match is a prefix/suffix inside a longer name.
    if before.map(is_ident).unwrap_or(false) {
        return false;
    }
    if after.map(is_ident).unwrap_or(false) {
        return false;
    }

    // Accept a delimiter on either side that resembles JSON, a NUL-terminated
    // string, a shell/env assignment, or the start/end of buffer.
    let is_delim = |b: u8| matches!(b, b'"' | b':' | b'=' | b'{' | b',' | b' ' | b'\t' | 0);
    let before_ok = before.map(is_delim).unwrap_or(true);
    let after_ok = after.map(is_delim).unwrap_or(true);
    before_ok && after_ok
}

// ============================
// Windows implementation
// ============================
#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::mem;
    use winapi::shared::minwindef::{DWORD, HMODULE, LPCVOID, LPVOID, MAX_PATH};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::{EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL};
    use winapi::um::winnt::{
        HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY,
        PAGE_READWRITE, PAGE_WRITECOPY, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// RAII wrapper for a Windows process HANDLE — ensures CloseHandle on all exit paths.
    pub(super) struct ScopedHandle(pub HANDLE);
    impl Drop for ScopedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub(super) async fn scan_windows() -> Vec<ScanFinding> {
        let proc = match find_roblox_process() {
            Some(p) => p,
            None => {
                return vec![ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Clean,
                    "Roblox process not found - memory scan skipped",
                    None,
                )];
            }
        };

        let pid = proc.pid;

        let raw_handle: HANDLE = unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid as DWORD)
        };
        if raw_handle.is_null() {
            return vec![ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Memory scan unavailable: insufficient permissions to read Roblox process (try running as Administrator)",
                Some(format!("PID: {}", pid)),
            )];
        }
        let handle = ScopedHandle(raw_handle);

        let mut findings = Vec::new();

        if !proc.path_looks_trusted {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Roblox-named process has an unexpected executable path — possible decoy / impersonation",
                Some(format!(
                    "PID: {} | Path: {}",
                    pid,
                    proc.exe_path.as_deref().unwrap_or("<unknown>")
                )),
            ));
        }

        // (1) Enumerate loaded modules, flag any outside trusted paths.
        findings.extend(scan_modules_windows(handle.0, pid));

        // (2) Walk committed regions.
        let mut tracker = FlagHitTracker::default();
        let flags = all_suspicious_flags();

        let mut address: usize = 0;
        let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let mem_info_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let mut rwx_hits = 0usize;
        let mut regions_scanned = 0usize;
        let mut regions_walked = 0usize;
        let mut scan_completed = false;

        loop {
            if regions_walked >= MAX_REGIONS_WALKED {
                break;
            }

            let result = unsafe {
                VirtualQueryEx(handle.0, address as LPCVOID, &mut mem_info, mem_info_size)
            };
            if result == 0 {
                // VirtualQueryEx returns 0 at end-of-user-address-space — treat as normal completion.
                scan_completed = true;
                break;
            }
            regions_walked += 1;

            let region_size = mem_info.RegionSize;
            let protect = mem_info.Protect;
            let state = mem_info.State;
            let region_type = mem_info.Type;

            // PAGE_GUARD pages raise STATUS_GUARD_PAGE_VIOLATION on read — skip.
            let is_guard = (protect & PAGE_GUARD) != 0;
            // Strip modifier bits for the readable/RWX classification.
            let base_protect = protect & 0xFF;

            if state == MEM_COMMIT && region_size > 0 && !is_guard {
                let is_rwx = base_protect == PAGE_EXECUTE_READWRITE
                    || base_protect == PAGE_EXECUTE_WRITECOPY;
                let is_readable = matches!(
                    base_protect,
                    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ
                ) || is_rwx;

                if is_rwx {
                    rwx_hits += 1;
                    findings.push(ScanFinding::new(
                        "memory_scanner",
                        ScanVerdict::Flagged,
                        format!(
                            "RWX memory region in Roblox process ({} KB) — possible shellcode or runtime-patched code",
                            region_size / 1024
                        ),
                        Some(format!(
                            "Address: 0x{:X}, Size: {} bytes, Protection: 0x{:X}",
                            address, region_size, protect
                        )),
                    ));
                }

                // Only scan heap/private/mapped regions for FFlag strings.
                // MEM_IMAGE regions are file-backed (module .text/.rdata) and
                // contain every flag name as a literal on a vanilla client,
                // producing false positives we can't disambiguate.
                let is_image = region_type == MEM_IMAGE;
                if is_readable && !is_image && region_size <= MAX_REGION_READ_BYTES {
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read: usize = 0;
                    let read_ok = unsafe {
                        ReadProcessMemory(
                            handle.0,
                            address as LPCVOID,
                            buffer.as_mut_ptr() as LPVOID,
                            region_size,
                            &mut bytes_read,
                        )
                    };
                    if read_ok != 0 && bytes_read > 0 {
                        buffer.truncate(bytes_read);
                        let region_findings =
                            search_buffer_for_flags(&buffer, address, &flags, &mut tracker);
                        findings.extend(region_findings);
                        regions_scanned += 1;
                    }
                }
            }

            // Advance. Guard against a zero-sized region returning — would otherwise infinite-loop.
            if region_size == 0 {
                break;
            }
            let next = address.wrapping_add(region_size);
            if next <= address {
                scan_completed = true;
                break;
            }
            address = next;
        }

        // Report partial vs complete scan honestly.
        if !scan_completed || regions_scanned == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Memory scan incomplete: region enumeration terminated early — cannot attest clean state",
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_scanned: {}",
                    pid, regions_walked, regions_scanned
                )),
            ));
        } else if tracker.total() == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "No suspicious FFlags found in Roblox process memory",
                Some(format!(
                    "PID: {}, regions_scanned: {}",
                    pid, regions_scanned
                )),
            ));
        }
        if rwx_hits == 0 && scan_completed {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "No RWX memory regions detected in Roblox process",
                Some(format!("PID: {}", pid)),
            ));
        }

        findings
    }

    /// Enumerate modules loaded into the target process and flag any whose path
    /// is not under a trusted directory. Uses a growing buffer so truncation
    /// is detected and compensated for.
    fn scan_modules_windows(handle: HANDLE, pid: u32) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
        let mut needed: DWORD;

        loop {
            let cb_bytes = (mem::size_of::<HMODULE>() * modules.len()) as DWORD;
            needed = 0;
            let ok = unsafe {
                EnumProcessModulesEx(
                    handle,
                    modules.as_mut_ptr(),
                    cb_bytes,
                    &mut needed,
                    LIST_MODULES_ALL,
                )
            };
            if ok == 0 {
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Suspicious,
                    "Could not enumerate modules in Roblox process",
                    Some(format!("PID: {}", pid)),
                ));
                return findings;
            }
            if (needed as usize) <= cb_bytes as usize {
                break;
            }
            // Truncated — grow the buffer and retry. Cap growth to prevent DoS.
            let new_len = (needed as usize / mem::size_of::<HMODULE>())
                .saturating_add(256)
                .min(256 * 1024);
            if new_len <= modules.len() {
                // Shouldn't happen, but stop retrying to avoid infinite growth.
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Suspicious,
                    "Module enumeration truncated; could not grow buffer",
                    Some(format!("PID: {}, needed: {}", pid, needed)),
                ));
                return findings;
            }
            modules.resize(new_len, std::ptr::null_mut());
        }

        let count = needed as usize / mem::size_of::<HMODULE>();

        let mut untrusted = 0usize;
        let mut total = 0usize;

        for i in 0..count {
            let hmod = modules[i];
            if hmod.is_null() {
                continue;
            }

            // Start with MAX_PATH; grow if GetModuleFileNameExW fills the buffer exactly.
            let mut buf: Vec<u16> = vec![0; MAX_PATH];
            let mut len = unsafe {
                GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as DWORD)
            };
            while len != 0 && (len as usize) == buf.len() {
                // Possibly truncated — grow and retry.
                let new_size = buf.len().saturating_mul(2).min(65_536);
                if new_size <= buf.len() {
                    break;
                }
                buf.resize(new_size, 0);
                len = unsafe {
                    GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as DWORD)
                };
            }
            if len == 0 {
                // Treat unreadable module name as suspicious — an attacker might
                // hide the path by racing a detach or via ACL restrictions.
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Suspicious,
                    "Module present in Roblox process with unreadable path",
                    Some(format!("PID: {}", pid)),
                ));
                continue;
            }

            total += 1;

            let path = String::from_utf16_lossy(&buf[..len as usize]);
            let lower = path.to_lowercase();

            if is_trusted_module_path(&lower) {
                continue;
            }

            untrusted += 1;
            let verdict = if is_high_risk_module_path(&lower) {
                ScanVerdict::Flagged
            } else {
                ScanVerdict::Suspicious
            };

            let filename = std::path::Path::new(&path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());

            findings.push(ScanFinding::new(
                "memory_scanner",
                verdict,
                format!("Untrusted module loaded into Roblox: \"{}\"", filename),
                Some(format!("Path: {}, PID: {}", path, pid)),
            ));
        }

        if untrusted == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "All loaded modules are from trusted locations",
                Some(format!("Modules inspected: {}, PID: {}", total, pid)),
            ));
        }

        findings
    }

    /// Known-folder-backed trusted roots for Roblox's own executable.
    pub(super) fn trusted_windows_roblox_roots() -> Vec<String> {
        let mut roots = Vec::new();
        if let Ok(pf) = std::env::var("ProgramFiles") {
            roots.push(format!("{}\\Roblox", pf));
            roots.push(format!("{}\\WindowsApps", pf));
        }
        if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
            roots.push(format!("{}\\Roblox", pfx86));
        }
        if let Ok(local) = std::env::var("LocalAppData") {
            roots.push(format!("{}\\Roblox", local));
            roots.push(format!("{}\\Packages", local)); // UWP sandbox state
        }
        roots
    }

    /// Known-folder-backed trusted roots for modules loaded into Roblox.
    /// Only the Windows system dirs and Roblox install dirs are allowed.
    fn trusted_module_roots_lower() -> Vec<String> {
        let mut roots = Vec::new();

        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        roots.push(format!("{}\\System32\\", sys_root).to_lowercase());
        roots.push(format!("{}\\SysWOW64\\", sys_root).to_lowercase());
        roots.push(format!("{}\\WinSxS\\", sys_root).to_lowercase());
        roots.push(format!("{}\\assembly\\", sys_root).to_lowercase());
        roots.push(format!("{}\\Microsoft.NET\\", sys_root).to_lowercase());

        if let Ok(pf) = std::env::var("ProgramFiles") {
            roots.push(format!("{}\\Roblox\\", pf).to_lowercase());
            roots.push(format!("{}\\WindowsApps\\", pf).to_lowercase());
        }
        if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
            roots.push(format!("{}\\Roblox\\", pfx86).to_lowercase());
        }
        if let Ok(local) = std::env::var("LocalAppData") {
            roots.push(format!("{}\\Roblox\\", local).to_lowercase());
            roots.push(format!("{}\\Packages\\", local).to_lowercase());
        }

        roots
    }

    /// A path is trusted if it starts with one of the known install/system roots.
    /// Uses prefix matching (not unanchored substring) to prevent attacker-controlled
    /// parent directories from whitelisting malicious DLLs.
    fn is_trusted_module_path(path_lower: &str) -> bool {
        // Reject paths containing `..` segments outright — GetModuleFileNameExW
        // normally returns canonical paths, so a `..` segment is suspicious on its own.
        if path_lower.contains("\\..\\") {
            return false;
        }
        let roots = trusted_module_roots_lower();
        roots.iter().any(|r| path_lower.starts_with(r))
    }

    /// A path is HIGH-RISK (Flagged, not just Suspicious) if it lives in an
    /// obviously user-writable tooling location. Only applied to modules that
    /// already failed the trusted-root check.
    fn is_high_risk_module_path(path_lower: &str) -> bool {
        const HIGH_RISK_SUBSTRS: &[&str] = &[
            "\\temp\\",
            "\\tmp\\",
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\public\\",
            "\\desktop\\",
            "\\injected\\",
        ];
        HIGH_RISK_SUBSTRS.iter().any(|s| path_lower.contains(s))
    }
}

#[cfg(target_os = "windows")]
fn trusted_windows_roblox_roots() -> Vec<String> {
    windows_impl::trusted_windows_roblox_roots()
}

#[cfg(target_os = "windows")]
async fn scan_windows() -> Vec<ScanFinding> {
    windows_impl::scan_windows().await
}

// ============================
// macOS implementation
// ============================
#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::mach_port::mach_port_deallocate;
    use mach2::message::mach_msg_type_number_t;
    use mach2::port::{mach_port_t, MACH_PORT_NULL};
    use mach2::traps::{mach_task_self, task_for_pid};
    use mach2::vm::{mach_vm_deallocate, mach_vm_read, mach_vm_region};
    use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
    use mach2::vm_region::{vm_region_basic_info_64, vm_region_info_t, VM_REGION_BASIC_INFO_64};
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t, vm_offset_t};
    use std::mem;

    /// RAII for a mach task send right.
    struct ScopedTaskPort(mach_port_t);
    impl Drop for ScopedTaskPort {
        fn drop(&mut self) {
            if self.0 != MACH_PORT_NULL {
                unsafe {
                    mach_port_deallocate(mach_task_self(), self.0);
                }
            }
        }
    }

    /// RAII for a mach_vm_read buffer.
    struct ScopedVmRead {
        task: mach_port_t,
        ptr: vm_offset_t,
        size: mach_msg_type_number_t,
    }
    impl Drop for ScopedVmRead {
        fn drop(&mut self) {
            if self.ptr != 0 {
                unsafe {
                    mach_vm_deallocate(
                        self.task,
                        self.ptr as mach_vm_address_t,
                        self.size as mach_vm_size_t,
                    );
                }
            }
        }
    }

    pub(super) async fn scan_macos() -> Vec<ScanFinding> {
        let proc = match find_roblox_process() {
            Some(p) => p,
            None => {
                return vec![ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Clean,
                    "Roblox process not found - memory scan skipped",
                    None,
                )];
            }
        };
        let pid = proc.pid;

        let mut raw_task: mach_port_t = MACH_PORT_NULL;
        let kr = unsafe { task_for_pid(mach_task_self(), pid as i32, &mut raw_task) };
        if kr != KERN_SUCCESS {
            return vec![ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Memory scan unavailable: task_for_pid denied. Run with sudo, or sign the scanner with com.apple.security.cs.debugger and a matching provisioning profile.",
                Some(format!("PID: {}, kern_return: {}", pid, kr)),
            )];
        }
        let task = ScopedTaskPort(raw_task);

        let mut findings = Vec::new();

        if !proc.path_looks_trusted {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Roblox-named process has an unexpected executable path — possible decoy / impersonation",
                Some(format!(
                    "PID: {} | Path: {}",
                    pid,
                    proc.exe_path.as_deref().unwrap_or("<unknown>")
                )),
            ));
        }

        let mut tracker = FlagHitTracker::default();
        let flags = all_suspicious_flags();

        let mut address: mach_vm_address_t = 0;
        let mut size: mach_vm_size_t = 0;
        let mut rwx_hits = 0usize;
        let mut regions_scanned = 0usize;
        let mut regions_walked = 0usize;
        let mut scan_completed = false;

        let info_count: u32 =
            (mem::size_of::<vm_region_basic_info_64>() / mem::size_of::<u32>()) as u32;

        loop {
            if regions_walked >= MAX_REGIONS_WALKED {
                break;
            }

            let mut info: vm_region_basic_info_64 = unsafe { mem::zeroed() };
            let mut info_count_mut: u32 = info_count;
            let mut object_name: mach_port_t = MACH_PORT_NULL;

            let kr = unsafe {
                mach_vm_region(
                    task.0,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut _ as vm_region_info_t,
                    &mut info_count_mut,
                    &mut object_name,
                )
            };

            // Release the object_name send right immediately — we don't use it.
            if object_name != MACH_PORT_NULL {
                unsafe {
                    mach_port_deallocate(mach_task_self(), object_name);
                }
            }

            if kr != KERN_SUCCESS {
                // End of address space → KERN_INVALID_ADDRESS — treat as normal completion.
                // Other kr values are errors; treat as early termination.
                const KERN_INVALID_ADDRESS: i32 = 1;
                if kr == KERN_INVALID_ADDRESS {
                    scan_completed = true;
                }
                break;
            }
            regions_walked += 1;

            let protection = info.protection;
            let is_readable = (protection & VM_PROT_READ) != 0;
            let is_rwx = (protection & (VM_PROT_WRITE | VM_PROT_EXECUTE))
                == (VM_PROT_WRITE | VM_PROT_EXECUTE);

            if is_rwx {
                rwx_hits += 1;
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Flagged,
                    format!(
                        "RWX memory region in Roblox process ({} KB) — possible shellcode or runtime-patched code",
                        size / 1024
                    ),
                    Some(format!(
                        "Address: 0x{:X}, Size: {} bytes, Protection: 0x{:X}",
                        address, size, protection
                    )),
                ));
            }

            if is_readable
                && size > 0
                && size as usize <= MAX_REGION_READ_BYTES
            {
                let mut data_ptr: vm_offset_t = 0;
                let mut data_size: mach_msg_type_number_t = 0;

                let read_kr = unsafe {
                    mach_vm_read(task.0, address, size, &mut data_ptr, &mut data_size)
                };

                if read_kr == KERN_SUCCESS && data_ptr != 0 {
                    // RAII owns the buffer — drops on all paths.
                    let _buf_guard = ScopedVmRead {
                        task: unsafe { mach_task_self() },
                        ptr: data_ptr,
                        size: data_size,
                    };
                    if (data_size as usize) > 0 && (data_size as usize) <= MAX_REGION_READ_BYTES {
                        let buffer = unsafe {
                            std::slice::from_raw_parts(
                                data_ptr as *const u8,
                                data_size as usize,
                            )
                        };
                        let region_findings = search_buffer_for_flags(
                            buffer,
                            address as usize,
                            &flags,
                            &mut tracker,
                        );
                        findings.extend(region_findings);
                        regions_scanned += 1;
                    }
                }
            }

            // Advance past this region. `mach_vm_region` sets `address` to the region base;
            // we step by `size`. Guard against zero-size and overflow.
            if size == 0 {
                break;
            }
            let next = address.wrapping_add(size);
            if next <= address {
                scan_completed = true;
                break;
            }
            address = next;
        }

        if !scan_completed || regions_scanned == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Memory scan incomplete: region enumeration terminated early — cannot attest clean state",
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_scanned: {}",
                    pid, regions_walked, regions_scanned
                )),
            ));
        } else if tracker.total() == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "No suspicious FFlags found in Roblox process memory",
                Some(format!(
                    "PID: {}, regions_scanned: {}",
                    pid, regions_scanned
                )),
            ));
        }
        if rwx_hits == 0 && scan_completed {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "No RWX memory regions detected in Roblox process",
                Some(format!("PID: {}", pid)),
            ));
        }

        findings
    }
}

#[cfg(target_os = "macos")]
async fn scan_macos() -> Vec<ScanFinding> {
    macos_impl::scan_macos().await
}
