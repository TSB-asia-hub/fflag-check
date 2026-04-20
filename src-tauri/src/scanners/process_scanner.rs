use std::collections::HashSet;
use sysinfo::System;

use crate::data::known_tools::{
    KNOWN_BOOTSTRAPPER_PROCESS_NAMES, KNOWN_PROCESS_NAMES, KNOWN_TOOL_FILENAMES,
};
use crate::models::{ScanFinding, ScanVerdict};

/// Scan running processes for known cheat/injection tools.
pub async fn scan() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    let mut sys = System::new_all();
    sys.refresh_all();

    let roblox_running = sys.processes().values().any(|p| {
        let name = p.name().to_string_lossy().to_lowercase();
        name.contains("roblox")
    });

    // Each PID is reported at most once even if both name and filename rules fire.
    let mut reported: HashSet<sysinfo::Pid> = HashSet::new();

    for (pid, process) in sys.processes() {
        if reported.contains(pid) {
            continue;
        }
        let proc_name = process.name().to_string_lossy().to_lowercase();
        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let exe_filename = process
            .exe()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut matched_via: Option<String> = None;

        for &known_name in KNOWN_PROCESS_NAMES {
            if proc_name.contains(known_name) {
                matched_via = Some(format!("matched: \"{}\"", known_name));
                break;
            }
        }

        if matched_via.is_none() && !exe_filename.is_empty() {
            for &known_file in KNOWN_TOOL_FILENAMES {
                if exe_filename.eq_ignore_ascii_case(known_file) {
                    matched_via = Some(format!("filename: \"{}\"", known_file));
                    break;
                }
            }
        }

        if let Some(reason) = matched_via {
            let verdict = if roblox_running {
                ScanVerdict::Flagged
            } else {
                ScanVerdict::Suspicious
            };
            findings.push(ScanFinding::new(
                "process_scanner",
                verdict,
                format!(
                    "Known tool process detected: \"{}\" ({})",
                    process.name().to_string_lossy(),
                    reason
                ),
                Some(format!("PID: {}, Path: {}", pid, exe_path)),
            ));
            reported.insert(*pid);
            continue;
        }

        // Legitimate bootstrapper launchers — informational only, never raise
        // the verdict. Per Roblox policy these are not cheat indicators.
        for &boot_name in KNOWN_BOOTSTRAPPER_PROCESS_NAMES {
            if proc_name.contains(boot_name) {
                findings.push(ScanFinding::new(
                    "process_scanner",
                    ScanVerdict::Clean,
                    format!(
                        "Bootstrapper running: \"{}\" (legitimate launcher; not a cheat indicator)",
                        process.name().to_string_lossy()
                    ),
                    Some(format!("PID: {}, Path: {}", pid, exe_path)),
                ));
                reported.insert(*pid);
                break;
            }
        }
    }

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "process_scanner",
            ScanVerdict::Clean,
            "No known cheat or injection tools detected in running processes",
            Some(format!("Scanned {} running processes", sys.processes().len())),
        ));
    }

    findings
}
