use std::path::PathBuf;

use crate::models::{ScanFinding, ScanReport};

/// Generate a signed scan report from a collection of findings.
pub fn generate_report(findings: Vec<ScanFinding>) -> ScanReport {
    let mut report = ScanReport::new();

    for finding in findings {
        report.add_finding(finding);
    }

    // Ensure overall verdict is computed
    report.overall_verdict = report.compute_verdict();

    // Sign the report with HMAC
    report.sign();

    report
}

/// Save a scan report as JSON to the user's desktop.
/// Verifies the HMAC before writing so a tampered frontend-supplied report
/// cannot produce a file whose signature disagrees with its contents.
/// Returns the file path on success.
pub fn save_report(report: &ScanReport) -> Result<String, String> {
    if !report.verify() {
        return Err(
            "Report HMAC signature is invalid — refusing to save a tampered report.".to_string(),
        );
    }

    let desktop = get_desktop_path().ok_or_else(|| "Could not determine desktop path".to_string())?;

    if !desktop.exists() {
        std::fs::create_dir_all(&desktop)
            .map_err(|e| format!("Could not create desktop directory: {}", e))?;
    }

    let timestamp = report.timestamp.format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("FlagCheck_Report_{}.json", timestamp);
    let file_path = desktop.join(&filename);

    let json = report.to_json();
    std::fs::write(&file_path, &json)
        .map_err(|e| format!("Could not write report file: {}", e))?;

    Ok(file_path.to_string_lossy().to_string())
}

/// Validate a report's HMAC signature from its JSON representation.
pub fn validate_report(json: &str) -> Result<bool, String> {
    let report: ScanReport =
        serde_json::from_str(json).map_err(|e| format!("Invalid report JSON: {}", e))?;

    Ok(report.verify())
}

/// Get the user's desktop path.
fn get_desktop_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .map(|p| PathBuf::from(p).join("Desktop"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|p| PathBuf::from(p).join("Desktop"))
    }
}
