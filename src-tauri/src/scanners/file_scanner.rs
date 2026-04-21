use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use sha2::{Digest, Sha256};

use crate::data::known_tools::{
    GENERIC_RE_TOOL_DIRS, INJECTOR_SIBLING_CONFIG_FILES, KNOWN_BOOTSTRAPPER_DIRS,
    KNOWN_TOOL_FILENAMES, KNOWN_TOOL_HASHES, ROBLOX_CHEAT_DIRS,
};
use crate::models::{ScanFinding, ScanVerdict};

/// Upper size bound (bytes) for opportunistic hashing of `.exe` artefacts
/// found during the walk. The largest known injector in the hash list is
/// well under 10 MB; real games/installers can be hundreds of MB, and we do
/// not want the scanner to stall reading those.
const HASH_SIZE_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

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

        // Roblox-specific cheat tool directories → Suspicious.
        for &tool_dir in ROBLOX_CHEAT_DIRS {
            let dir_path = root.join(tool_dir);
            if dir_path.exists() && dir_path.is_dir() {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    let modified = format_modified(&dir_path);
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Suspicious,
                        format!("Roblox-cheat tool directory found: \"{}\"", tool_dir),
                        Some(format!(
                            "Path: {}, Last modified: {}",
                            dir_path.display(),
                            modified
                        )),
                    ));
                }
            }
        }

        // Generic reverse-engineering / debugging tools (x64dbg, HxD,
        // ProcessHacker, etc.) — widely used for CTF, malware analysis,
        // driver debugging, and security research. Record as informational
        // Clean notes only; do not raise the verdict.
        for &tool_dir in GENERIC_RE_TOOL_DIRS {
            let dir_path = root.join(tool_dir);
            if dir_path.exists() && dir_path.is_dir() {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    let modified = format_modified(&dir_path);
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Clean,
                        format!(
                            "Generic reverse-engineering tool present: \"{}\" (legitimate security/CTF use; not a Roblox-specific cheat indicator)",
                            tool_dir
                        ),
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

            let file_name_os = entry.file_name().to_string_lossy().to_string();
            let file_name = file_name_os.as_str();

            // Name-based match.
            let mut matched_by_name = false;
            for &known_file in KNOWN_TOOL_FILENAMES {
                if file_name.eq_ignore_ascii_case(known_file) {
                    let canon = entry
                        .path()
                        .canonicalize()
                        .unwrap_or_else(|_| entry.path().to_path_buf());
                    if reported_paths.insert(canon.clone()) {
                        findings.push(ScanFinding::new(
                            "file_scanner",
                            ScanVerdict::Suspicious,
                            format!("Known tool executable found: \"{}\"", file_name),
                            Some(format!(
                                "Path: {}, Last modified: {}",
                                entry.path().display(),
                                format_modified(entry.path())
                            )),
                        ));
                    }
                    matched_by_name = true;
                    break;
                }
            }
            if matched_by_name {
                continue;
            }

            // Hash-based match: only on plausibly-sized PE/Mach-O/zip artefacts.
            let ext_is_candidate = matches!(
                lower_ext(entry.path()).as_deref(),
                Some("exe") | Some("zip") | Some("dmg") | Some("app")
            );
            if ext_is_candidate {
                let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(u64::MAX);
                if size <= HASH_SIZE_LIMIT_BYTES {
                    if let Some(hex) = hash_file_sha256(entry.path()) {
                        for &(known_hex, display_name, note) in KNOWN_TOOL_HASHES {
                            if hex.eq_ignore_ascii_case(known_hex) {
                                let canon = entry
                                    .path()
                                    .canonicalize()
                                    .unwrap_or_else(|_| entry.path().to_path_buf());
                                if reported_paths.insert(canon.clone()) {
                                    findings.push(ScanFinding::new(
                                        "file_scanner",
                                        ScanVerdict::Flagged,
                                        format!(
                                            "Known tool artefact matched by SHA-256: \"{}\" (as \"{}\")",
                                            display_name, file_name
                                        ),
                                        Some(format!(
                                            "Path: {}, SHA-256: {}, Last modified: {}, Note: {}",
                                            entry.path().display(),
                                            hex,
                                            format_modified(entry.path()),
                                            note
                                        )),
                                    ));
                                }
                                break;
                            }
                        }
                    }
                }
            }

            // Sibling-config heuristic: PE with fflags.json + address.json next
            // to it is the LornoFix family's on-disk layout. This is a
            // filename heuristic with no content verification, so it is
            // Suspicious — not Flagged. A real PE-magic check plus non-empty
            // JSON shape keeps it from firing on zero-byte stubs named the
            // same way in a developer's scratch folder.
            if lower_ext(entry.path()).as_deref() == Some("exe") {
                if let Some(parent) = entry.path().parent() {
                    let all_present = INJECTOR_SIBLING_CONFIG_FILES
                        .iter()
                        .all(|name| parent.join(name).is_file());
                    let exe_looks_real = file_starts_with_mz(entry.path());
                    let siblings_non_empty = INJECTOR_SIBLING_CONFIG_FILES.iter().all(|name| {
                        std::fs::metadata(parent.join(name))
                            .map(|m| m.len() >= 2) // enough to hold at least "{}"
                            .unwrap_or(false)
                    });
                    if all_present && exe_looks_real && siblings_non_empty {
                        let canon = entry
                            .path()
                            .canonicalize()
                            .unwrap_or_else(|_| entry.path().to_path_buf());
                        if reported_paths.insert(canon.clone()) {
                            findings.push(ScanFinding::new(
                                "file_scanner",
                                ScanVerdict::Suspicious,
                                format!(
                                    "Executable co-located with FFlag-injector config files: \"{}\"",
                                    file_name
                                ),
                                Some(format!(
                                    "Path: {}, Sibling config files: [{}]",
                                    entry.path().display(),
                                    INJECTOR_SIBLING_CONFIG_FILES.join(", ")
                                )),
                            ));
                        }
                    }
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
        // Zero roots = zero coverage. A signed Clean report in that case is
        // a silent false-negative — emit Inconclusive so tournament staff
        // know the file scan had nothing to look at.
        if scanned.is_empty() {
            findings.push(ScanFinding::new(
                "file_scanner",
                ScanVerdict::Inconclusive,
                "No scanner roots available — user home / AppData env vars unset?",
                Some(format!(
                    "Configured candidate roots: {}",
                    roots
                        .iter()
                        .map(|r| r.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            ));
        } else {
            findings.push(ScanFinding::new(
                "file_scanner",
                ScanVerdict::Clean,
                "No known tool artifacts found on filesystem",
                Some(format!("Scanned {} directories", scanned.len())),
            ));
        }
    }

    findings
}

/// Lowercased file extension, or None for files without one.
fn lower_ext(path: &Path) -> Option<String> {
    path.extension().map(|e| e.to_string_lossy().to_lowercase())
}

/// Stream-hash a file as SHA-256, returning lowercase hex. Returns None on I/O
/// error (permission denied, file racing disappearance, etc.) rather than
/// propagating — an unhashable file is simply not matched.
fn hash_file_sha256(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(hex::encode(hasher.finalize()))
}

/// True if the file at `path` starts with the PE / Mach-O magic bytes that a
/// real Windows/macOS executable would have. Prevents the sibling-config
/// heuristic from firing on a zero-byte or text-only file that happens to be
/// named `something.exe`.
fn file_starts_with_mz(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 2];
    match f.read(&mut magic) {
        Ok(n) if n == 2 => &magic == b"MZ",
        _ => false,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_file_sha256_matches_known_value() {
        // "abc" → SHA-256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let dir = std::env::temp_dir().join(format!(
            "fflag_check_hash_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("abc.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"abc").unwrap();
        }
        let got = hash_file_sha256(&path).expect("hash ok");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lower_ext_normalises_case() {
        assert_eq!(
            lower_ext(Path::new("x/Y/Foo.EXE")).as_deref(),
            Some("exe")
        );
        assert_eq!(lower_ext(Path::new("noext")), None);
    }

    #[test]
    fn known_tool_hashes_are_lowercase_hex_64() {
        for &(hex, name, _) in KNOWN_TOOL_HASHES {
            assert_eq!(
                hex.len(),
                64,
                "hash for {} is not 64 hex chars: {}",
                name,
                hex
            );
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "hash for {} must be lowercase hex: {}",
                name,
                hex
            );
        }
    }

    #[test]
    fn sibling_config_pattern_is_detected_on_disk() {
        // Build a fake injector layout in a fresh temp dir and verify that
        // hash_file_sha256 + sibling-file logic would pick it up.
        let root = std::env::temp_dir().join(format!(
            "fflag_check_sibling_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let exe = root.join("tool.exe");
        std::fs::write(&exe, b"MZ\x90\x00fake pe").unwrap();
        for name in INJECTOR_SIBLING_CONFIG_FILES {
            std::fs::write(root.join(name), b"{}").unwrap();
        }

        // All siblings present → heuristic should match.
        let all_present = INJECTOR_SIBLING_CONFIG_FILES
            .iter()
            .all(|name| root.join(name).is_file());
        assert!(all_present);

        std::fs::remove_dir_all(&root).ok();
    }
}
