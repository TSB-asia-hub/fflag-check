use std::collections::HashSet;
use std::path::PathBuf;
use walkdir::WalkDir;

use crate::data::known_tools::{
    KNOWN_BOOTSTRAPPER_DIRS, KNOWN_TOOL_DIRS, KNOWN_TOOL_FILENAMES,
};
use crate::models::{ScanFinding, ScanVerdict};

/// Scan the filesystem for known tool artifacts.
pub async fn scan() -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let roots = get_search_roots();

    // Track every absolute path we've already reported on, so the same file
    // isn't double-flagged when overlapping search roots cause it to be
    // visited via two different walks.
    let mut reported_paths: HashSet<PathBuf> = HashSet::new();

    for root in &roots {
        if !root.exists() {
            continue;
        }

        // Tool directories
        for &tool_dir in KNOWN_TOOL_DIRS {
            let dir_path = root.join(tool_dir);
            if dir_path.exists() && dir_path.is_dir() {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    let modified = format_modified(&dir_path);
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Suspicious,
                        format!("Known tool directory found: \"{}\"", tool_dir),
                        Some(format!(
                            "Path: {}, Last modified: {}",
                            dir_path.display(),
                            modified
                        )),
                    ));
                }
            }
        }

        // Bootstrapper directories — informational only (legitimate launchers
        // per Roblox policy, not cheat indicators).
        for &boot_dir in KNOWN_BOOTSTRAPPER_DIRS {
            let dir_path = root.join(boot_dir);
            if dir_path.exists() && dir_path.is_dir() {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Clean,
                        format!(
                            "Bootstrapper directory present: \"{}\" (legitimate launcher; not a cheat indicator)",
                            boot_dir
                        ),
                        Some(format!("Path: {}", dir_path.display())),
                    ));
                }
            }
        }

        // Tool executables (depth-limited walk).
        let walker = WalkDir::new(root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            if !entry.file_type().is_file() {
                continue;
            }

            let file_name = entry.file_name().to_string_lossy();

            for &known_file in KNOWN_TOOL_FILENAMES {
                if file_name.eq_ignore_ascii_case(known_file) {
                    let canon = entry
                        .path()
                        .canonicalize()
                        .unwrap_or_else(|_| entry.path().to_path_buf());
                    if reported_paths.insert(canon.clone()) {
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
                            "file_scanner",
                            ScanVerdict::Suspicious,
                            format!("Known tool executable found: \"{}\"", file_name),
                            Some(format!(
                                "Path: {}, Last modified: {}",
                                entry.path().display(),
                                modified
                            )),
                        ));
                    }
                    break;
                }
            }
        }
    }

    if findings.is_empty() {
        let scanned: Vec<String> = roots
            .iter()
            .filter(|r| r.exists())
            .map(|r| r.display().to_string())
            .collect();
        findings.push(ScanFinding::new(
            "file_scanner",
            ScanVerdict::Clean,
            "No known tool artifacts found on filesystem",
            Some(format!("Scanned {} directories", scanned.len())),
        ));
    }

    findings
}

fn format_modified(path: &std::path::Path) -> String {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get the list of root directories to scan. Each root is walked at most
/// once; we deliberately do NOT include LOCALAPPDATA / APPDATA / USERPROFILE
/// as scan roots in addition to their known subdirectories — that produced
/// duplicate findings via overlapping walks.
fn get_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let lad = PathBuf::from(&local_app_data);
            roots.push(lad.join("Voidstrap"));
            roots.push(lad.join("Bloxstrap"));
            roots.push(lad.join("Fishstrap"));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            roots.push(PathBuf::from(&appdata).join("FFlagToolkit"));
        }
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let up = PathBuf::from(&userprofile);
            roots.push(up.join("Downloads"));
            roots.push(up.join("Desktop"));
            roots.push(up.join("Documents"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            roots.push(home.join("Library").join("Application Support"));
            roots.push(home.join("Library").join("Roblox"));
            roots.push(home.join("Downloads"));
            roots.push(home.join("Desktop"));
            roots.push(home.join("Documents"));
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(home) = home_dir() {
            roots.push(home.join("Downloads"));
            roots.push(home.join("Desktop"));
            roots.push(home.join("Documents"));
        }
    }

    roots
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}
