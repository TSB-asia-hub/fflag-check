use crate::data::suspicious_flags::{CRITICAL_FLAGS, HIGH_FLAGS, MEDIUM_FLAGS, get_flag_category, get_flag_description};
use crate::models::{ScanFinding, ScanVerdict};

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

/// All suspicious flag names combined for memory search.
fn all_suspicious_flags() -> Vec<&'static str> {
    let mut flags = Vec::new();
    flags.extend_from_slice(CRITICAL_FLAGS);
    flags.extend_from_slice(HIGH_FLAGS);
    flags.extend_from_slice(MEDIUM_FLAGS);
    flags
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

/// Find the Roblox process PID.
fn find_roblox_pid() -> Option<u32> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    #[cfg(target_os = "windows")]
    let target_name = "robloxplayerbeta";
    #[cfg(target_os = "macos")]
    let target_name = "robloxplayer";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let target_name = "roblox";

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        if name.contains(target_name) {
            return Some(pid.as_u32());
        }
    }
    None
}

/// Search a memory buffer for suspicious FFlag strings.
fn search_buffer_for_flags(
    buffer: &[u8],
    base_address: usize,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let suspicious_flags = all_suspicious_flags();

    // Convert buffer to a string slice for searching (lossy is fine, we're looking for ASCII)
    // We search for each flag name as raw bytes for efficiency
    for &flag_name in &suspicious_flags {
        let flag_bytes = flag_name.as_bytes();
        if flag_bytes.len() > buffer.len() {
            continue;
        }

        // Simple byte pattern search
        for i in 0..=(buffer.len() - flag_bytes.len()) {
            if &buffer[i..i + flag_bytes.len()] == flag_bytes {
                let severity = crate::data::suspicious_flags::get_flag_severity(flag_name);
                let address = base_address + i;
                let category = get_flag_category(flag_name).unwrap_or("UNKNOWN");
                let desc = get_flag_description(flag_name);
                let detail_suffix = desc
                    .map(|d| format!(" | {}", d))
                    .unwrap_or_default();

                findings.push(ScanFinding::new(
                    "memory_scanner",
                    severity,
                    format!(
                        "FFlag found in Roblox memory: \"{}\"",
                        flag_name
                    ),
                    Some(format!("Memory address: 0x{:X} | Category: {}{}", address, category, detail_suffix)),
                ));
                break; // Only report the first occurrence of each flag
            }
        }
    }

    findings
}

// ============================
// Windows implementation
// ============================
#[cfg(target_os = "windows")]
async fn scan_windows() -> Vec<ScanFinding> {
    use winapi::shared::minwindef::{DWORD, LPCVOID, LPVOID};
    use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winnt::{
        HANDLE, MEM_COMMIT, PAGE_READONLY, PAGE_READWRITE,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, MEMORY_BASIC_INFORMATION,
    };
    use std::mem;
    use std::ptr;

    let pid = match find_roblox_pid() {
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

    let handle: HANDLE = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid as DWORD)
    };

    if handle.is_null() {
        return vec![ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Suspicious,
            "Memory scan unavailable: insufficient permissions to read Roblox process",
            Some(format!("PID: {}", pid)),
        )];
    }

    let mut findings = Vec::new();
    let mut address: usize = 0;
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mem_info_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

    // Max memory to scan (4GB limit to avoid hanging)
    let max_address: usize = 0x1_0000_0000;
    // Max region size to read at once (16MB)
    let max_region_size: usize = 16 * 1024 * 1024;

    loop {
        if address >= max_address {
            break;
        }

        let result = unsafe {
            VirtualQueryEx(
                handle,
                address as LPCVOID,
                &mut mem_info,
                mem_info_size,
            )
        };

        if result == 0 {
            break;
        }

        let region_size = mem_info.RegionSize;
        let protect = mem_info.Protect;
        let state = mem_info.State;

        // Only scan committed, readable regions
        if state == MEM_COMMIT
            && (protect == PAGE_READWRITE || protect == PAGE_READONLY)
            && region_size > 0
            && region_size <= max_region_size
        {
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read: usize = 0;

            let read_ok = unsafe {
                ReadProcessMemory(
                    handle,
                    address as LPCVOID,
                    buffer.as_mut_ptr() as LPVOID,
                    region_size,
                    &mut bytes_read,
                )
            };

            if read_ok != 0 && bytes_read > 0 {
                buffer.truncate(bytes_read);
                let region_findings = search_buffer_for_flags(&buffer, address);
                findings.extend(region_findings);
            }
        }

        // Move to next region
        address = address.wrapping_add(region_size);
        if address == 0 {
            break; // Wrapped around
        }
    }

    unsafe {
        CloseHandle(handle);
    }

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Clean,
            "No suspicious FFlags found in Roblox process memory",
            Some(format!("PID: {}", pid)),
        ));
    }

    findings
}

// ============================
// macOS implementation
// ============================
#[cfg(target_os = "macos")]
async fn scan_macos() -> Vec<ScanFinding> {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::port::mach_port_t;
    use mach2::traps::task_for_pid;
    use mach2::vm::mach_vm_read;
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

    let pid = match find_roblox_pid() {
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

    // Get the mach task port for the target process
    let mut task: mach_port_t = 0;
    let kr = unsafe { task_for_pid(mach2::traps::mach_task_self(), pid as i32, &mut task) };

    if kr != KERN_SUCCESS {
        return vec![ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Suspicious,
            "Memory scan unavailable: insufficient permissions (task_for_pid failed, requires root/SIP disabled)",
            Some(format!("PID: {}, kern_return: {}", pid, kr)),
        )];
    }

    let mut findings = Vec::new();

    // Scan memory regions
    // We use mach_vm_region to enumerate regions, then mach_vm_read to read them.
    // For simplicity, scan a reasonable address range.
    let mut address: mach_vm_address_t = 0;
    let max_address: mach_vm_address_t = 0x1_0000_0000; // 4GB
    let max_region_size: mach_vm_size_t = 16 * 1024 * 1024; // 16MB
    let _step_size: mach_vm_size_t = 4096; // Page size

    // Use mach_vm_region to enumerate readable regions
    use mach2::vm_region::{vm_region_basic_info_64, vm_region_info_t, VM_REGION_BASIC_INFO_64};
    use mach2::vm::mach_vm_region;
    use std::mem;

    let mut info: vm_region_basic_info_64 = unsafe { mem::zeroed() };
    let mut info_count: u32;
    let mut object_name: mach_port_t = 0;
    let mut size: mach_vm_size_t = 0;

    loop {
        if address >= max_address {
            break;
        }

        info_count = mem::size_of::<vm_region_basic_info_64>() as u32 / 4;
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as vm_region_info_t,
                &mut info_count,
                &mut object_name,
            )
        };

        if kr != KERN_SUCCESS {
            break;
        }

        // Check if the region is readable
        let readable = (info.protection & 0x01) != 0; // VM_PROT_READ = 1
        if readable && size > 0 && size <= max_region_size {
            use mach2::vm_types::vm_offset_t;
            use mach2::message::mach_msg_type_number_t;

            let mut data_ptr: vm_offset_t = 0;
            let mut data_size: mach_msg_type_number_t = 0;

            let read_kr = unsafe {
                mach_vm_read(
                    task,
                    address,
                    size,
                    &mut data_ptr as *mut vm_offset_t,
                    &mut data_size as *mut mach_msg_type_number_t,
                )
            };

            if read_kr == KERN_SUCCESS && data_size > 0 {
                let buffer = unsafe {
                    std::slice::from_raw_parts(data_ptr as *const u8, data_size as usize)
                };
                let region_findings =
                    search_buffer_for_flags(buffer, address as usize);
                findings.extend(region_findings);

                // Deallocate the read buffer
                unsafe {
                    mach2::vm::mach_vm_deallocate(
                        mach2::traps::mach_task_self(),
                        data_ptr as mach_vm_address_t,
                        data_size as mach_vm_size_t,
                    );
                }
            }
        }

        // Move to next region
        address = address.wrapping_add(size);
        if address == 0 || size == 0 {
            break;
        }
    }

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Clean,
            "No suspicious FFlags found in Roblox process memory",
            Some(format!("PID: {}", pid)),
        ));
    }

    findings
}
