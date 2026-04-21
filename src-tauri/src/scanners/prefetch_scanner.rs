use crate::models::ScanFinding;
#[cfg(not(target_os = "windows"))]
use crate::models::ScanVerdict;

/// Scan Windows Prefetch files for evidence of known tools.
/// Returns empty on non-Windows platforms.
pub async fn scan() -> Vec<ScanFinding> {
    #[cfg(target_os = "windows")]
    {
        scan_windows_prefetch().await
    }

    #[cfg(not(target_os = "windows"))]
    {
        vec![ScanFinding::new(
            "prefetch_scanner",
            ScanVerdict::Clean,
            "Prefetch scan skipped - Windows only feature",
            None,
        )]
    }
}

#[cfg(target_os = "windows")]
async fn scan_windows_prefetch() -> Vec<ScanFinding> {
    use crate::data::known_tools::KNOWN_TOOL_FILENAMES;
    use crate::models::ScanVerdict;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    // Only surface prefetch hits for tools executed in the recent past.
    // Prefetch keeps up to 1024 .pf files over many weeks; a run from
    // months ago of CheatEngine for an unrelated single-player game is not
    // cheat evidence against today's Roblox session. 7 days is a wide-
    // enough window to catch "ran it an hour before the tournament" while
    // not accusing anyone based on historical artifacts.
    const RECENT_WINDOW: Duration = Duration::from_secs(60 * 60 * 24 * 7);

    let mut findings = Vec::new();
    let prefetch_dir = Path::new(r"C:\Windows\Prefetch");

    if !prefetch_dir.exists() {
        // Prefetch disabled (SSD tuners, enterprise GPO) — coverage is
        // genuinely zero, so surface as Inconclusive rather than silently
        // contributing nothing.
        findings.push(ScanFinding::new(
            "prefetch_scanner",
            ScanVerdict::Inconclusive,
            "Windows Prefetch directory not present — cannot attest on historical tool execution",
            None,
        ));
        return findings;
    }

    let entries = match std::fs::read_dir(prefetch_dir) {
        Ok(e) => e,
        Err(_) => {
            findings.push(ScanFinding::new(
                "prefetch_scanner",
                ScanVerdict::Inconclusive,
                "Could not read Windows Prefetch directory (permission denied?)",
                None,
            ));
            return findings;
        }
    };

    let now = SystemTime::now();
    let mut stale_hits: usize = 0;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();

        // Prefetch files have the .pf extension
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext != "pf" {
            continue;
        }

        let file_name = match path.file_stem() {
            Some(name) => name.to_string_lossy().to_string(),
            None => continue,
        };

        // Prefetch filenames are formatted as TOOLNAME.EXE-HASH
        let tool_name = extract_prefetch_tool_name(&file_name);
        if tool_name.is_empty() {
            continue;
        }

        let modified_time = entry.metadata().ok().and_then(|m| m.modified().ok());
        let age = modified_time.and_then(|t| now.duration_since(t).ok());
        let is_recent = age.map(|a| a <= RECENT_WINDOW).unwrap_or(false);

        for &known_file in KNOWN_TOOL_FILENAMES {
            if tool_name.eq_ignore_ascii_case(known_file) {
                if !is_recent {
                    stale_hits += 1;
                    break;
                }
                let modified = modified_time
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                findings.push(ScanFinding::new(
                    "prefetch_scanner",
                    ScanVerdict::Suspicious,
                    format!(
                        "Recent prefetch evidence of known tool (last {} days): \"{}\"",
                        RECENT_WINDOW.as_secs() / 86400,
                        tool_name
                    ),
                    Some(format!(
                        "Prefetch file: {}, Last modified: {}",
                        path.display(),
                        modified
                    )),
                ));
                break;
            }
        }
    }

    if stale_hits > 0 {
        // Record historical hits as Clean informational so tournament staff
        // can see they exist without letting them drive the verdict.
        findings.push(ScanFinding::new(
            "prefetch_scanner",
            ScanVerdict::Clean,
            format!(
                "{} historical prefetch entries for known tools (older than {} days; not factored into verdict)",
                stale_hits,
                RECENT_WINDOW.as_secs() / 86400
            ),
            None,
        ));
    }

    // If we didn't add a Suspicious/stale finding above, add a clean
    // confirmation. `stale_hits > 0` still counts as having found *something*
    // worth reporting, so the Clean summary isn't added in that case.
    let saw_anything = !findings.is_empty();
    if !saw_anything {
        findings.push(ScanFinding::new(
            "prefetch_scanner",
            ScanVerdict::Clean,
            "No recent prefetch evidence of known tools",
            None,
        ));
    }

    findings
}

/// Extract the tool name (e.g., "CHEATENGINE.EXE") from a prefetch file stem
/// like "CHEATENGINE.EXE-ABCD1234".
#[cfg(target_os = "windows")]
fn extract_prefetch_tool_name(file_stem: &str) -> String {
    // The format is TOOLNAME.EXE-HEXHASH
    // We find the last '-' and take everything before it
    if let Some(dash_pos) = file_stem.rfind('-') {
        file_stem[..dash_pos].to_string()
    } else {
        file_stem.to_string()
    }
}
