use std::path::PathBuf;

use crate::data::flag_allowlist::is_allowed_flag;
use crate::data::suspicious_flags::{get_flag_category, get_flag_description, get_flag_severity};
use crate::models::{ScanFinding, ScanVerdict};

/// Scan Roblox ClientAppSettings.json and bootstrapper configs for suspicious FFlags.
pub async fn scan() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    // 1. Check native Roblox ClientAppSettings.json
    let config_paths = get_client_settings_paths();
    for path in &config_paths {
        if !path.exists() {
            continue;
        }

        findings.push(ScanFinding::new(
            "client_settings_scanner",
            ScanVerdict::Suspicious,
            "ClientAppSettings.json file exists (this folder is not created by default)",
            Some(format!("Path: {}", path.display())),
        ));

        match std::fs::read_to_string(path) {
            Ok(content) => {
                check_flat_json_flags(&content, path, &mut findings);
            }
            Err(e) => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Suspicious,
                    format!("Could not read ClientAppSettings.json: {}", e),
                    Some(format!("Path: {}", path.display())),
                ));
            }
        }
    }

    // 2. Check bootstrapper configs (AppleBlox, Bloxstrap, etc.)
    scan_bootstrapper_configs(&mut findings);

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "client_settings_scanner",
            ScanVerdict::Clean,
            "No FFlag override files found — no ClientAppSettings.json or bootstrapper configs detected",
            None,
        ));
    }

    findings
}

/// Check a flat JSON key-value map of FFlags (the ClientAppSettings.json format).
fn check_flat_json_flags(content: &str, path: &PathBuf, findings: &mut Vec<ScanFinding>) {
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            findings.push(ScanFinding::new(
                "client_settings_scanner",
                ScanVerdict::Suspicious,
                format!("Could not parse JSON: {}", e),
                Some(format!("Path: {}", path.display())),
            ));
            return;
        }
    };

    let map = match parsed.as_object() {
        Some(m) => m,
        None => return,
    };

    if map.is_empty() {
        return;
    }

    for (key, value) in map {
        if is_allowed_flag(key) {
            continue;
        }

        let severity = get_flag_severity(key);
        let category = get_flag_category(key).unwrap_or("UNKNOWN");
        let desc = get_flag_description(key);
        let detail_suffix = desc
            .map(|d| format!(" | {}", d))
            .unwrap_or_default();

        match severity {
            ScanVerdict::Flagged => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Flagged,
                    format!("Critical FFlag detected: \"{}\" = {}", key, value),
                    Some(format!("Path: {} | Category: {}{}", path.display(), category, detail_suffix)),
                ));
            }
            ScanVerdict::Suspicious => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Suspicious,
                    format!("Suspicious FFlag detected: \"{}\" = {}", key, value),
                    Some(format!("Path: {} | Category: {}{}", path.display(), category, detail_suffix)),
                ));
            }
            ScanVerdict::Clean => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Suspicious,
                    format!("Unknown non-allowlisted FFlag: \"{}\" = {}", key, value),
                    Some(format!("Path: {}", path.display())),
                ));
            }
        }
    }
}

/// Scan bootstrapper configuration files for FFlag settings.
/// Supports: AppleBlox (macOS), Bloxstrap (Windows), Fishstrap, Voidstrap.
fn scan_bootstrapper_configs(findings: &mut Vec<ScanFinding>) {
    let configs = get_bootstrapper_config_paths();

    for (bootstrapper_name, paths) in configs {
        for path in paths {
            if !path.exists() {
                continue;
            }

            findings.push(ScanFinding::new(
                "client_settings_scanner",
                ScanVerdict::Suspicious,
                format!("{} configuration found", bootstrapper_name),
                Some(format!("Path: {}", path.display())),
            ));

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let parsed: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // AppleBlox format: { "flags": [ { "flag": "Name", "enabled": true, "value": "X" }, ... ] }
            // Also in profiles: same format at top level
            if let Some(flags_array) = parsed.get("flags").and_then(|f| f.as_array()) {
                check_bootstrapper_flag_array(flags_array, &bootstrapper_name, &path, findings);
            }

            // AppleBlox fastflags.json has a different structure — check for FFlag-like keys
            if let Some(obj) = parsed.as_object() {
                // Check for graphics.unlock_fps, visual.debug_sky, etc.
                if let Some(graphics) = obj.get("graphics").and_then(|g| g.as_object()) {
                    if graphics.get("unlock_fps").and_then(|v| v.as_bool()) == Some(true) {
                        findings.push(ScanFinding::new(
                            "client_settings_scanner",
                            ScanVerdict::Suspicious,
                            format!("{}: FPS unlock enabled", bootstrapper_name),
                            Some(format!("Path: {}", path.display())),
                        ));
                    }
                }
                if let Some(visual) = obj.get("visual").and_then(|v| v.as_object()) {
                    if visual.get("debug_sky").and_then(|v| v.as_bool()) == Some(true) {
                        findings.push(ScanFinding::new(
                            "client_settings_scanner",
                            ScanVerdict::Suspicious,
                            format!("{}: Debug sky (gray sky) enabled", bootstrapper_name),
                            Some(format!("Path: {}", path.display())),
                        ));
                    }
                }
                if let Some(utility) = obj.get("utility").and_then(|u| u.as_object()) {
                    if utility.get("telemetry").and_then(|v| v.as_bool()) == Some(false) {
                        findings.push(ScanFinding::new(
                            "client_settings_scanner",
                            ScanVerdict::Suspicious,
                            format!("{}: Telemetry disabled", bootstrapper_name),
                            Some(format!("Path: {}", path.display())),
                        ));
                    }
                }
            }

            // Bloxstrap/Voidstrap format: flat JSON { "FlagName": value, ... }
            if let Some(obj) = parsed.as_object() {
                let has_fflags = obj.keys().any(|k| {
                    k.starts_with("FFlag")
                        || k.starts_with("DFInt")
                        || k.starts_with("DFFlag")
                        || k.starts_with("FInt")
                        || k.starts_with("FLog")
                        || k.starts_with("SFFlag")
                });
                if has_fflags {
                    check_flat_json_flags(&content, &path, findings);
                }
            }
        }
    }
}

/// Check an array of AppleBlox-style flag objects.
fn check_bootstrapper_flag_array(
    flags: &[serde_json::Value],
    bootstrapper_name: &str,
    path: &PathBuf,
    findings: &mut Vec<ScanFinding>,
) {
    for flag_obj in flags {
        let flag_name = match flag_obj.get("flag").and_then(|f| f.as_str()) {
            Some(name) => name,
            None => continue,
        };

        let enabled = flag_obj
            .get("enabled")
            .and_then(|e| e.as_bool())
            .unwrap_or(true);

        if !enabled {
            continue;
        }

        let value = flag_obj
            .get("value")
            .map(|v| {
                if let Some(s) = v.as_str() {
                    s.to_string()
                } else {
                    v.to_string()
                }
            })
            .unwrap_or_default();

        if is_allowed_flag(flag_name) {
            continue;
        }

        let severity = get_flag_severity(flag_name);
        let category = get_flag_category(flag_name).unwrap_or("UNKNOWN");
        let desc = get_flag_description(flag_name);
        let detail_suffix = desc
            .map(|d| format!(" | {}", d))
            .unwrap_or_default();

        match severity {
            ScanVerdict::Flagged => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Flagged,
                    format!(
                        "{}: Critical FFlag \"{}\" = {}",
                        bootstrapper_name, flag_name, value
                    ),
                    Some(format!("Path: {} | Category: {}{}", path.display(), category, detail_suffix)),
                ));
            }
            ScanVerdict::Suspicious => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Suspicious,
                    format!(
                        "{}: Suspicious FFlag \"{}\" = {}",
                        bootstrapper_name, flag_name, value
                    ),
                    Some(format!("Path: {} | Category: {}{}", path.display(), category, detail_suffix)),
                ));
            }
            ScanVerdict::Clean => {
                findings.push(ScanFinding::new(
                    "client_settings_scanner",
                    ScanVerdict::Suspicious,
                    format!(
                        "{}: Non-allowlisted FFlag \"{}\" = {}",
                        bootstrapper_name, flag_name, value
                    ),
                    Some(format!("Path: {}", path.display())),
                ));
            }
        }
    }
}

/// Get platform-specific paths to ClientAppSettings.json.
fn get_client_settings_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let roblox_versions = PathBuf::from(&local_app_data)
                .join("Roblox")
                .join("Versions");

            if roblox_versions.exists() {
                if let Ok(entries) = std::fs::read_dir(&roblox_versions) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let version_dir = entry.path();
                        if version_dir.is_dir() {
                            let settings_path = version_dir
                                .join("ClientSettings")
                                .join("ClientAppSettings.json");
                            if settings_path.exists() {
                                paths.push(settings_path);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(&home);

            // Primary macOS path: ~/Library/Roblox/ClientSettings/ClientAppSettings.json
            let roblox_path = home_path
                .join("Library")
                .join("Roblox")
                .join("ClientSettings")
                .join("ClientAppSettings.json");
            paths.push(roblox_path);
        }
    }

    paths
}

/// Get bootstrapper config file paths for all known bootstrappers.
fn get_bootstrapper_config_paths() -> Vec<(&'static str, Vec<PathBuf>)> {
    let mut configs = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(&home);
            let appleblox_dir = home_path
                .join("Library")
                .join("Application Support")
                .join("AppleBlox");

            if appleblox_dir.exists() {
                let mut appleblox_paths = vec![
                    appleblox_dir.join("config").join("fastflags.json"),
                ];

                // Also check all profile files
                let profiles_dir = appleblox_dir.join("config").join("profiles");
                if profiles_dir.exists() {
                    if let Ok(entries) = std::fs::read_dir(&profiles_dir) {
                        for entry in entries.filter_map(|e| e.ok()) {
                            let path = entry.path();
                            if path.extension().map(|e| e == "json").unwrap_or(false) {
                                appleblox_paths.push(path);
                            }
                        }
                    }
                }

                configs.push(("AppleBlox", appleblox_paths));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let lad = PathBuf::from(&local_app_data);

            // Bloxstrap
            let bloxstrap_flags = lad
                .join("Bloxstrap")
                .join("Modifications")
                .join("ClientSettings")
                .join("ClientAppSettings.json");
            if bloxstrap_flags.exists() {
                configs.push(("Bloxstrap", vec![bloxstrap_flags]));
            }

            // Voidstrap
            let voidstrap_flags = lad
                .join("Voidstrap")
                .join("Modifications")
                .join("ClientSettings")
                .join("ClientAppSettings.json");
            if voidstrap_flags.exists() {
                configs.push(("Voidstrap", vec![voidstrap_flags]));
            }

            // Fishstrap
            let fishstrap_flags = lad
                .join("Fishstrap")
                .join("Modifications")
                .join("ClientSettings")
                .join("ClientAppSettings.json");
            if fishstrap_flags.exists() {
                configs.push(("Fishstrap", vec![fishstrap_flags]));
            }
        }

        if let Ok(appdata) = std::env::var("APPDATA") {
            // FFlagToolkit (fflag-injector)
            let fftoolkit_config = PathBuf::from(&appdata)
                .join("FFlagToolkit")
                .join("fflag.json");
            if fftoolkit_config.exists() {
                configs.push(("FFlagToolkit", vec![fftoolkit_config]));
            }
        }
    }

    configs
}
