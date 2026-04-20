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

    let mut findings = Vec::new();
    let prefetch_dir = Path::new(r"C:\Windows\Prefetch");

    if !prefetch_dir.exists() {
        return findings;
    }

    let entries = match std::fs::read_dir(prefetch_dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };

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
        // We need to extract just the TOOLNAME.EXE part
        // Find the last dash followed by hex characters
        let tool_name = extract_prefetch_tool_name(&file_name);
        if tool_name.is_empty() {
            continue;
        }

        for &known_file in KNOWN_TOOL_FILENAMES {
            if tool_name.eq_ignore_ascii_case(known_file) {
                let modified = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                findings.push(ScanFinding::new(
                    "prefetch_scanner",
                    ScanVerdict::Suspicious,
                    format!(
                        "Prefetch evidence of known tool: \"{}\"",
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

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "prefetch_scanner",
            ScanVerdict::Clean,
            "No known tool execution traces found in Windows Prefetch",
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
