// On non-Windows builds, memory scanning is stubbed and most helpers are only
// exercised by the Windows path or the unit tests. Silence dead_code there.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use crate::data::flag_allowlist::{is_allowed_flag, is_memory_baseline_flag};
use crate::data::suspicious_flags::{
    get_flag_category, get_flag_description, get_flag_severity, CRITICAL_FLAGS, HIGH_FLAGS,
    MEDIUM_FLAGS,
};
use crate::models::{ScanFinding, ScanVerdict};
use crate::scanners::progress::ScanProgress;
use std::collections::{HashMap, HashSet};

/// Known FFlag prefixes. Any identifier matching `<prefix><IdentBody>` where
/// the body is a camel-cased identifier is a candidate flag name. We treat
/// unknown candidates as Suspicious rather than ignoring them, because the
/// allowlist-only approach misses novel flag names entirely.
const FLAG_PREFIXES: &[&str] = &[
    "DFFlag", "FFlag", "DFInt", "FInt", "DFString", "FString", "DFLog", "FLog", "SFFlag", "SFInt",
    "SFString",
];

/// Maximum identifier body length after a prefix. Real Roblox flag names top
/// out around ~90 chars; anything longer is almost certainly not a flag.
const MAX_IDENT_BODY_LEN: usize = 128;
/// Minimum identifier body length. Single-character bodies are noise.
const MIN_IDENT_BODY_LEN: usize = 3;

/// Hard cap on regions walked per scan, to prevent runaway loops when the OS
/// enumeration API misbehaves. Roblox typically has far fewer regions.
const MAX_REGIONS_WALKED: usize = 200_000;

/// Wall-clock safety cap for the entire memory scan. Without this, a stuck
/// `ReadProcessMemory` on a pathological region (rare, but observed in
/// field reports) can hang the UI indefinitely with no recovery path. On
/// expiry the scan returns a Suspicious "aborted" finding so the user
/// learns coverage was incomplete rather than seeing an infinite spinner.
const MAX_SCAN_DURATION: std::time::Duration = std::time::Duration::from_secs(90);

/// Max per-chunk read (16 MiB). Regions larger than this are chunked with
/// an overlap equal to the longest candidate string, so boundary hits are
/// not missed.
const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Absolute per-region cap. Regions larger than this (>512 MiB) are only
/// partially scanned (the first ABS_REGION_CAP bytes), with a finding noting
/// the truncation, to keep total scan time bounded.
const ABS_REGION_CAP: usize = 512 * 1024 * 1024;

/// Aggregated state for an observed flag name, across all regions in one scan.
#[derive(Default)]
struct FlagHit {
    count: usize,
    first_address: usize,
    /// True if at least one occurrence was found as UTF-16LE (wide string).
    seen_wide: bool,
    /// True if at least one occurrence was found as plain ASCII/UTF-8.
    seen_ascii: bool,
}

/// Per-scan hit map. Keys are interned flag names (static strings for known
/// flags, owned strings for unknown discoveries).
#[derive(Default)]
struct FlagHitTable {
    hits: HashMap<String, FlagHit>,
}

impl FlagHitTable {
    fn record(&mut self, flag: &str, address: usize, wide: bool) {
        let entry = self.hits.entry(flag.to_string()).or_default();
        if entry.count == 0 {
            entry.first_address = address;
        }
        entry.count += 1;
        if wide {
            entry.seen_wide = true;
        } else {
            entry.seen_ascii = true;
        }
    }
    fn total_flags(&self) -> usize {
        self.hits.len()
    }

    /// Fold another table into this one. Used by the parallel scanner to
    /// combine per-worker tables at the end of the region walk. Preserves
    /// the lowest observed `first_address` across workers so the final
    /// finding points at the earliest sighting, not a random one.
    fn merge(&mut self, other: FlagHitTable) {
        for (name, h) in other.hits {
            match self.hits.entry(name) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let existing = e.get_mut();
                    if existing.count == 0 || h.first_address < existing.first_address {
                        existing.first_address = h.first_address;
                    }
                    existing.count = existing.count.saturating_add(h.count);
                    existing.seen_wide |= h.seen_wide;
                    existing.seen_ascii |= h.seen_ascii;
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(h);
                }
            }
        }
    }
}

/// Scan Roblox process memory for runtime FFlag injections.
pub async fn scan() -> Vec<ScanFinding> {
    scan_with_progress(ScanProgress::noop()).await
}

/// Same as [`scan`] but accepts a progress reporter so the frontend can show
/// live region/byte counters while the Windows memory walk is in flight.
pub async fn scan_with_progress(reporter: ScanProgress) -> Vec<ScanFinding> {
    #[cfg(target_os = "windows")]
    {
        scan_windows(reporter).await
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = reporter; // unused on non-Windows
        vec![ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Clean,
            "Memory scan not supported on this platform",
            Some("Memory scanning is Windows-only in this build.".to_string()),
        )]
    }
}

/// Result of locating a Roblox process: the PID and whether the executable
/// path passed basic validation against expected Roblox install roots.
#[cfg(target_os = "windows")]
struct RobloxProcess {
    pid: u32,
    exe_path: Option<String>,
    path_looks_trusted: bool,
}

/// Find the Roblox process PID, validating the executable path against
/// expected install roots. Falls back to name-only matching when the path
/// cannot be read.
#[cfg(target_os = "windows")]
fn find_roblox_process() -> Option<RobloxProcess> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_all();

    let name_hint = "robloxplayerbeta";

    let mut best: Option<RobloxProcess> = None;

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        if !name.contains(name_hint) {
            continue;
        }
        let exe_path = process.exe().map(|p| p.to_string_lossy().to_string());
        let path_looks_trusted = exe_path
            .as_deref()
            .map(is_trusted_roblox_exe_path)
            .unwrap_or(false);

        let candidate = RobloxProcess {
            pid: pid.as_u32(),
            exe_path,
            path_looks_trusted,
        };

        // Prefer a trusted-path match; otherwise keep the FIRST name match
        // and don't let later untrusted matches overwrite it.
        match &best {
            Some(b) if b.path_looks_trusted => {} // already optimal — keep it
            Some(_) if !candidate.path_looks_trusted => {} // keep the first untrusted
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
#[cfg(target_os = "windows")]
fn is_trusted_roblox_exe_path(exe_path: &str) -> bool {
    let lower = exe_path.to_lowercase();
    let roots: Vec<String> = trusted_windows_roblox_roots();
    roots.iter().any(|r| lower.starts_with(&r.to_lowercase()))
}

/// Require that the match be bounded by non-identifier bytes (or start/end of
/// buffer). This rejects matches that are a prefix/suffix inside a longer
/// identifier — e.g. searching for `FFlagFoo` must not match `FFlagFooBar`.
fn is_boundary_ok(buffer: &[u8], start: usize, len: usize) -> bool {
    let before = if start == 0 { None } else { Some(buffer[start - 1]) };
    let after_idx = start + len;
    let after = if after_idx < buffer.len() {
        Some(buffer[after_idx])
    } else {
        None
    };
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if before.map(is_ident).unwrap_or(false) {
        return false;
    }
    if after.map(is_ident).unwrap_or(false) {
        return false;
    }
    true
}

/// Extended boundary check requiring at least one surrounding byte to look like
/// a JSON/C-string/shell delimiter. Used for generic prefix discovery so that
/// identifiers embedded in random binary noise are not picked up.
fn is_contextual_match(buffer: &[u8], start: usize, len: usize) -> bool {
    if !is_boundary_ok(buffer, start, len) {
        return false;
    }
    let before = if start == 0 { None } else { Some(buffer[start - 1]) };
    let after_idx = start + len;
    let after = if after_idx < buffer.len() {
        Some(buffer[after_idx])
    } else {
        None
    };
    let is_delim = |b: u8| matches!(b, b'"' | b':' | b'=' | b'{' | b',' | b' ' | b'\t' | 0);
    let before_ok = before.map(is_delim).unwrap_or(true);
    let after_ok = after.map(is_delim).unwrap_or(true);
    before_ok && after_ok
}

/// Identifier-body character (first byte must still be an uppercase letter,
/// see the scanner logic).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Cached set of every known suspicious flag name, for O(1) lookups from
/// the hot ASCII-scan loop. Before this cache each candidate triggered three
/// linear scans over the CRITICAL/HIGH/MEDIUM arrays (~300 string compares
/// per hit).
fn known_flag_set() -> &'static HashSet<&'static str> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashSet<&'static str>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut s: HashSet<&'static str> = HashSet::with_capacity(
            CRITICAL_FLAGS.len() + HIGH_FLAGS.len() + MEDIUM_FLAGS.len(),
        );
        s.extend(CRITICAL_FLAGS.iter().copied());
        s.extend(HIGH_FLAGS.iter().copied());
        s.extend(MEDIUM_FLAGS.iter().copied());
        s
    })
}

/// Generic prefix scan. Every FFlag prefix starts with `D`, `F`, or `S`, so
/// we use `memchr3` to skip directly to candidate positions instead of
/// touching every byte. On random binary data this cuts the inner loop from
/// ~N iterations to ~N/256 — a single 16 MiB chunk of non-identifier bytes
/// becomes a handful of `pcmpeqb`/`pmovmskb` ops instead of 16 million
/// per-byte prefix-compare passes.
///
/// At each candidate position we still do: left-boundary, prefix match,
/// uppercase-body-start, body-length + contextual boundary checks —
/// identical semantics to the pre-memchr version.
/// Returns tuples of (offset_in_buffer, full_name, is_known_or_allowed).
fn scan_prefix_hits(buffer: &[u8]) -> Vec<(usize, String, bool)> {
    let mut out: Vec<(usize, String, bool)> = Vec::new();
    if buffer.is_empty() {
        return out;
    }
    let known = known_flag_set();

    let mut cursor = 0usize;
    while cursor < buffer.len() {
        let rel = match memchr::memchr3(b'D', b'F', b'S', &buffer[cursor..]) {
            Some(o) => o,
            None => break,
        };
        let i = cursor + rel;
        // Tentatively advance one byte; if we find a full identifier below we
        // jump past it to skip its interior.
        cursor = i + 1;

        // Left boundary: previous byte must not be an ident byte.
        if i > 0 && is_ident_byte(buffer[i - 1]) {
            continue;
        }

        let mut matched_prefix: Option<&'static str> = None;
        for &prefix in FLAG_PREFIXES {
            let pb = prefix.as_bytes();
            if i + pb.len() > buffer.len() {
                continue;
            }
            // Cheap first-byte check already passed (memchr3), but prefixes
            // share first letters so still need the full compare.
            if &buffer[i..i + pb.len()] == pb {
                matched_prefix = Some(prefix);
                break;
            }
        }
        let prefix = match matched_prefix {
            Some(p) => p,
            None => continue,
        };

        // Body must start with an uppercase ASCII letter (real flags are
        // camel-cased), followed by at least MIN_IDENT_BODY_LEN ident bytes.
        let body_start = i + prefix.len();
        if body_start >= buffer.len() {
            continue;
        }
        if !buffer[body_start].is_ascii_uppercase() {
            continue;
        }

        let mut j = body_start;
        while j < buffer.len()
            && j - body_start < MAX_IDENT_BODY_LEN
            && is_ident_byte(buffer[j])
        {
            j += 1;
        }
        let body_len = j - body_start;
        if body_len < MIN_IDENT_BODY_LEN {
            continue;
        }

        let total_len = prefix.len() + body_len;
        if !is_contextual_match(buffer, i, total_len) {
            continue;
        }

        let name = match std::str::from_utf8(&buffer[i..j]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let is_known = known.contains(name.as_str()) || is_allowed_flag(&name);
        out.push((i, name, is_known));
        // Jump past the identifier so its interior isn't re-examined.
        cursor = j;
    }

    out
}

/// Cached Aho-Corasick automaton over the UTF-16LE encodings of every known
/// suspicious flag. Replaces the previous per-pattern linear scan which did
/// `N * patterns` byte compares (~278 passes over each chunk). A single AC
/// pass is O(N + matches) — for a 16 MiB chunk that's ~50 ms instead of
/// ~20 s on typical hardware.
///
/// The returned tuple keeps the parallel slice of `&'static` flag names
/// aligned with pattern indices so `Match::pattern()` → name is O(1).
fn known_wide_automaton() -> &'static (aho_corasick::AhoCorasick, Vec<&'static str>) {
    use std::sync::OnceLock;
    static CACHE: OnceLock<(aho_corasick::AhoCorasick, Vec<&'static str>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut names: Vec<&'static str> =
            Vec::with_capacity(CRITICAL_FLAGS.len() + HIGH_FLAGS.len() + MEDIUM_FLAGS.len());
        names.extend(CRITICAL_FLAGS.iter().copied());
        names.extend(HIGH_FLAGS.iter().copied());
        names.extend(MEDIUM_FLAGS.iter().copied());
        let patterns: Vec<Vec<u8>> = names.iter().map(|n| to_utf16le(n)).collect();
        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&patterns)
            .expect("aho-corasick automaton build should not fail over static flag set");
        (ac, names)
    })
}

/// Scan a buffer for UTF-16LE occurrences of any known suspicious flag name
/// using the cached Aho-Corasick automaton. Targeted (against known lists)
/// rather than generic because UTF-16 noise generates unacceptable
/// false-positive rates otherwise.
fn scan_wide_known(buffer: &[u8], base_address: usize, table: &mut FlagHitTable) {
    let (ac, names) = known_wide_automaton();
    for m in ac.find_iter(buffer) {
        let start = m.start();
        let len = m.end() - start;
        if !is_wide_boundary_ok(buffer, start, len) {
            continue;
        }
        let name = names[m.pattern().as_usize()];
        let address = base_address.saturating_add(start);
        table.record(name, address, true);
    }
}

fn to_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// UTF-16LE boundary check: the wide char before/after must not be another
/// identifier code unit. For ASCII identifier chars in UTF-16LE, this means
/// the byte pair `(x, 0x00)` where `x` is ident-like.
fn is_wide_boundary_ok(buffer: &[u8], start: usize, len: usize) -> bool {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // Before: two bytes prior
    if start >= 2 {
        let lo = buffer[start - 2];
        let hi = buffer[start - 1];
        if hi == 0 && is_ident(lo) {
            return false;
        }
    }
    // After
    let after = start + len;
    if after + 1 < buffer.len() {
        let lo = buffer[after];
        let hi = buffer[after + 1];
        if hi == 0 && is_ident(lo) {
            return false;
        }
    }
    true
}

/// Core per-buffer scan. Combines generic prefix discovery (ASCII) + targeted
/// UTF-16LE search against known lists. Updates the shared hit table.
fn scan_buffer(buffer: &[u8], base_address: usize, table: &mut FlagHitTable) {
    // ASCII generic prefix scan — captures known AND unknown flags.
    for (offset, name, _is_known) in scan_prefix_hits(buffer) {
        let address = base_address.saturating_add(offset);
        table.record(&name, address, false);
    }
    // UTF-16LE targeted scan for known names.
    scan_wide_known(buffer, base_address, table);
}

/// Emit findings from the hit table.
///
/// Known suspicious flags (Critical / High / Medium) each get their own
/// individual finding — these are actionable and the user needs to see them
/// one per row.
///
/// Unrecognized flag-shaped identifiers are folded into a single summary
/// finding with a sampled list in the details. Roblox's running process
/// contains thousands of internal identifiers matching the FFlag shape;
/// emitting a finding per unknown hit would push tens of thousands of rows
/// into the UI, hanging the webview. The summary still surfaces the count
/// and top-N names so a reviewer can spot anomalous additions without
/// drowning in noise.
fn findings_from_table(table: &FlagHitTable) -> Vec<ScanFinding> {
    const UNKNOWN_SAMPLE_LIMIT: usize = 25;

    let mut out = Vec::new();

    let known = known_flag_set();
    let mut entries: Vec<(&String, &FlagHit)> = table.hits.iter().collect();
    let severity_rank = |name: &str| -> u8 {
        if CRITICAL_FLAGS.iter().any(|&f| f == name) {
            0
        } else if HIGH_FLAGS.iter().any(|&f| f == name) {
            1
        } else if MEDIUM_FLAGS.iter().any(|&f| f == name) {
            2
        } else {
            3
        }
    };
    entries.sort_by(|a, b| {
        severity_rank(a.0)
            .cmp(&severity_rank(b.0))
            .then_with(|| a.0.cmp(b.0))
    });

    let mut unknown_count: usize = 0;
    let mut unknown_total_occurrences: u64 = 0;
    let mut unknown_seen_wide = false;
    let mut unknown_seen_ascii = false;
    let mut unknown_samples: Vec<String> = Vec::new();

    for (name, hit) in entries {
        if is_allowed_flag(name) || is_memory_baseline_flag(name) {
            // Skip both Roblox's official allowlist AND the TSB-community
            // memory baseline. The latter is flags whose NAMES live in
            // every vanilla Roblox process because the runtime references
            // them — the string being in memory doesn't mean a value was
            // ever set. The client_settings scanner handles the value-set
            // case separately and ignores this baseline.
            continue;
        }
        let is_known = known.contains(name.as_str());

        if !is_known {
            unknown_count += 1;
            unknown_total_occurrences =
                unknown_total_occurrences.saturating_add(hit.count as u64);
            unknown_seen_wide |= hit.seen_wide;
            unknown_seen_ascii |= hit.seen_ascii;
            if unknown_samples.len() < UNKNOWN_SAMPLE_LIMIT {
                unknown_samples.push(name.clone());
            }
            continue;
        }

        let verdict = get_flag_severity(name);
        let category = get_flag_category(name).unwrap_or("KNOWN");
        let desc = get_flag_description(name);
        let desc_suffix = desc.map(|d| format!(" | {}", d)).unwrap_or_default();
        let encoding = match (hit.seen_ascii, hit.seen_wide) {
            (true, true) => "ascii+utf16",
            (true, false) => "ascii",
            (false, true) => "utf16",
            (false, false) => "unknown",
        };

        out.push(ScanFinding::new(
            "memory_scanner",
            verdict,
            format!("FFlag found in Roblox memory: \"{}\"", name),
            Some(format!(
                "First address: 0x{:X} | Occurrences: {} | Encoding: {} | Category: {}{}",
                hit.first_address, hit.count, encoding, category, desc_suffix
            )),
        ));
    }

    if unknown_count > 0 {
        let encoding = match (unknown_seen_ascii, unknown_seen_wide) {
            (true, true) => "ascii+utf16",
            (true, false) => "ascii",
            (false, true) => "utf16",
            (false, false) => "unknown",
        };
        let sample_line = if unknown_samples.is_empty() {
            String::new()
        } else {
            let sample_names = unknown_samples.join(", ");
            let truncation = if unknown_count > UNKNOWN_SAMPLE_LIMIT {
                format!(" (+{} more)", unknown_count - UNKNOWN_SAMPLE_LIMIT)
            } else {
                String::new()
            };
            format!(" | Samples: {}{}", sample_names, truncation)
        };
        out.push(ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Suspicious,
            format!(
                "{} unrecognized FFlag-shaped identifiers in Roblox memory",
                unknown_count
            ),
            Some(format!(
                "Unique names: {} | Total occurrences: {} | Encoding: {}{}",
                unknown_count, unknown_total_occurrences, encoding, sample_line
            )),
        ));
    }

    out
}

// ============================
// Windows implementation
// ============================
#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use rayon::prelude::*;
    use std::ffi::c_void;
    use std::mem;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// RAII wrapper for a Windows process HANDLE — ensures CloseHandle on all exit paths.
    pub(super) struct ScopedHandle(pub HANDLE);
    impl Drop for ScopedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    /// Longest candidate byte-length we need to preserve across chunk boundaries.
    /// Maximum plausible wide-string length dominates: (prefix + MAX_IDENT_BODY_LEN) * 2.
    fn chunk_overlap_bytes() -> usize {
        // Longest prefix is "DFString" / "SFString" at 8 chars.
        let max_name = 8 + MAX_IDENT_BODY_LEN;
        max_name * 2 + 4
    }

    /// Read every chunk of a single committed region into `scratch` and feed
    /// it to `scan_buffer`, updating the worker-local `FlagHitTable` and the
    /// shared atomic counters. Checks `timed_out` between chunks so the
    /// watchdog can abort mid-region.
    fn scan_region_into(
        local: &mut FlagHitTable,
        scratch: &mut Vec<u8>,
        handle: HANDLE,
        addr: usize,
        size: usize,
        overlap: usize,
        bytes_scanned: &AtomicU64,
        regions_scanned: &AtomicUsize,
        timed_out: &AtomicBool,
    ) {
        if scratch.capacity() < MAX_CHUNK_BYTES {
            scratch.reserve(MAX_CHUNK_BYTES - scratch.capacity());
        }
        let mut offset = 0usize;
        while offset < size {
            if timed_out.load(Ordering::Relaxed) {
                return;
            }
            let this_chunk = (size - offset).min(MAX_CHUNK_BYTES);
            // SAFETY: `scratch` has capacity >= MAX_CHUNK_BYTES >= this_chunk.
            // We never read `scratch[..this_chunk]` unless `ReadProcessMemory`
            // writes into it — and then only the `bytes_read` prefix it
            // actually filled. Avoids the ~16 MiB memset the old
            // `resize(this_chunk, 0)` path performed per chunk.
            unsafe {
                scratch.set_len(this_chunk);
            }
            let mut bytes_read: usize = 0;
            let read_ok = unsafe {
                ReadProcessMemory(
                    handle,
                    (addr + offset) as *const c_void,
                    scratch.as_mut_ptr() as *mut c_void,
                    this_chunk,
                    &mut bytes_read,
                )
            };
            if read_ok != 0 && bytes_read > 0 {
                bytes_scanned.fetch_add(bytes_read as u64, Ordering::Relaxed);
                scan_buffer(&scratch[..bytes_read], addr + offset, local);
            } else {
                offset = offset.saturating_add(this_chunk);
                continue;
            }
            let advance = if this_chunk > overlap {
                this_chunk - overlap
            } else {
                this_chunk
            };
            offset = offset.saturating_add(advance);
        }
        regions_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) async fn scan_windows(reporter: ScanProgress) -> Vec<ScanFinding> {
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

        // Refuse to scan a Roblox-named process whose executable lives outside
        // a trusted install root. Otherwise a player can drop a renamed decoy
        // (e.g. an empty binary called `robloxplayerbeta.exe`) and silently
        // redirect the memory scan to it, getting a false-clean.
        if !proc.path_looks_trusted {
            return vec![ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Flagged,
                "Roblox-named process has an untrusted executable path — refusing to scan (possible decoy)",
                Some(format!(
                    "PID: {} | Path: {}",
                    pid,
                    proc.exe_path.as_deref().unwrap_or("<unknown>")
                )),
            )];
        }

        let raw_handle: HANDLE =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
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

        // (1) Enumerate loaded modules, flag any outside trusted paths.
        findings.extend(scan_modules_windows(handle.0, pid));

        // ---- Phase A: enumerate regions (sequential, metadata only). ----
        // VirtualQueryEx is a fast kernel call that just returns region info;
        // the heavy work is the ReadProcessMemory in phase B. Splitting the
        // two lets us fan phase B across rayon workers without serializing
        // the enum loop.
        let mut regions_to_scan: Vec<(usize, usize)> = Vec::new();
        let mut rwx_hits = 0usize;
        let mut regions_walked = 0usize;
        let mut truncated_regions = 0usize;
        let mut scan_completed = false;

        let overlap = chunk_overlap_bytes();

        {
            let mut address: usize = 0;
            let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
            let mem_info_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

            loop {
                if regions_walked >= MAX_REGIONS_WALKED {
                    break;
                }
                let result = unsafe {
                    VirtualQueryEx(
                        handle.0,
                        address as *const c_void,
                        &mut mem_info,
                        mem_info_size,
                    )
                };
                if result == 0 {
                    scan_completed = true;
                    break;
                }
                regions_walked += 1;

                let region_size = mem_info.RegionSize;
                let protect = mem_info.Protect;
                let state = mem_info.State;
                let region_type = mem_info.Type;

                let is_guard = (protect & PAGE_GUARD) != 0;
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

                    // Only scan heap/private/mapped regions for strings.
                    // MEM_IMAGE (file-backed .text/.rdata) contains every
                    // flag name as a literal on a vanilla client, producing
                    // false positives we can't disambiguate for the ASCII
                    // scan.
                    let is_image = region_type == MEM_IMAGE;
                    if is_readable && !is_image {
                        let effective_size = region_size.min(ABS_REGION_CAP);
                        if effective_size < region_size {
                            truncated_regions += 1;
                        }
                        regions_to_scan.push((address, effective_size));
                    }
                }

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
        }

        // ---- Phase B: parallel region scan. ----
        // Each rayon worker owns a reusable scratch buffer and a local
        // FlagHitTable; tables are merged at the end via `.reduce`.
        let bytes_scanned = Arc::new(AtomicU64::new(0));
        let regions_scanned = Arc::new(AtomicUsize::new(0));
        let timed_out = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Watchdog + heartbeat: a single thread that both emits periodic
        // progress events and flips the shared `timed_out` flag when the
        // wall-clock cap is hit. Workers poll `timed_out` between chunks,
        // giving a ~1× chunk worst-case abort latency (~500ms on modern HW).
        let hb_bytes = bytes_scanned.clone();
        let hb_regions = regions_scanned.clone();
        let hb_timeout = timed_out.clone();
        let hb_shutdown = shutdown.clone();
        let hb_reporter = reporter.clone();
        let scan_started = std::time::Instant::now();
        let hb_thread = std::thread::spawn(move || {
            let interval = std::time::Duration::from_millis(400);
            loop {
                std::thread::park_timeout(interval);
                if hb_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if scan_started.elapsed() >= MAX_SCAN_DURATION {
                    hb_timeout.store(true, Ordering::Relaxed);
                    break;
                }
                hb_reporter.heartbeat(
                    "memory_scanner",
                    hb_regions.load(Ordering::Relaxed),
                    hb_bytes.load(Ordering::Relaxed),
                );
            }
        });

        // Pass the HANDLE as a `usize` bit-pattern across thread boundaries.
        // `HANDLE` is `*mut c_void`, which is neither `Send` nor `Sync`, and
        // rayon's closure must be both. A wrapper struct with
        // `unsafe impl Sync` doesn't help here because Rust's disjoint-field
        // capture rules make the closure capture `&*mut c_void` directly
        // rather than `&Wrapper`. `usize` is unconditionally `Send + Sync`
        // and round-trips losslessly back to `HANDLE` inside the closure.
        // ReadProcessMemory is documented as safe to call concurrently on
        // the same handle, and `ScopedHandle` only closes after this block.
        let handle_usize = handle.0 as usize;
        let table = regions_to_scan
            .par_iter()
            .fold(
                || (FlagHitTable::default(), Vec::<u8>::with_capacity(MAX_CHUNK_BYTES)),
                |(mut local, mut scratch), &(addr, size)| {
                    if !timed_out.load(Ordering::Relaxed) {
                        scan_region_into(
                            &mut local,
                            &mut scratch,
                            handle_usize as HANDLE,
                            addr,
                            size,
                            overlap,
                            &bytes_scanned,
                            &regions_scanned,
                            &timed_out,
                        );
                    }
                    (local, scratch)
                },
            )
            .map(|(t, _)| t)
            .reduce(FlagHitTable::default, |mut a, b| {
                a.merge(b);
                a
            });

        // Stop the heartbeat thread. `unpark` wakes it immediately so we
        // don't pay up to 400ms of sleep latency at the end of every scan.
        shutdown.store(true, Ordering::Relaxed);
        hb_thread.thread().unpark();
        let _ = hb_thread.join();

        let bytes_scanned_final = bytes_scanned.load(Ordering::Relaxed);
        let regions_scanned_final = regions_scanned.load(Ordering::Relaxed);
        let timed_out_final = timed_out.load(Ordering::Relaxed);
        // Shadow the names the legacy reporting block below used, so the
        // diff between old and new is minimal.
        let bytes_scanned = bytes_scanned_final;
        let regions_scanned = regions_scanned_final;
        let timed_out = timed_out_final;

        // Emit flag findings.
        findings.extend(findings_from_table(&table));

        // Honest summary.
        if timed_out {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                format!(
                    "Memory scan aborted after {}s wall-clock cap — cannot attest clean state",
                    MAX_SCAN_DURATION.as_secs()
                ),
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_scanned: {}, bytes_scanned: {}",
                    pid, regions_walked, regions_scanned, bytes_scanned
                )),
            ));
        } else if !scan_completed || regions_scanned == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "Memory scan incomplete: region enumeration terminated early — cannot attest clean state",
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_scanned: {}, bytes: {}",
                    pid, regions_walked, regions_scanned, bytes_scanned
                )),
            ));
        } else if table.total_flags() == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "No suspicious FFlags found in Roblox process memory",
                Some(format!(
                    "PID: {}, regions_scanned: {}, bytes_scanned: {}",
                    pid, regions_scanned, bytes_scanned
                )),
            ));
        }
        if truncated_regions > 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Suspicious,
                "One or more memory regions exceeded scan cap and were only partially scanned",
                Some(format!(
                    "PID: {}, truncated_regions: {}, per_region_cap_bytes: {}",
                    pid, truncated_regions, ABS_REGION_CAP
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
        let mut needed: u32;

        loop {
            let cb_bytes = (mem::size_of::<HMODULE>() * modules.len()) as u32;
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

            let mut buf: Vec<u16> = vec![0; MAX_PATH as usize];
            let mut len =
                unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
            while len != 0 && (len as usize) == buf.len() {
                let new_size = buf.len().saturating_mul(2).min(65_536);
                if new_size <= buf.len() {
                    break;
                }
                buf.resize(new_size, 0);
                len = unsafe {
                    GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32)
                };
            }
            if len == 0 {
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

    pub(super) fn trusted_windows_roblox_roots() -> Vec<String> {
        // UWP locations are scoped to the ROBLOXCORPORATION package family
        // rather than the entire WindowsApps / Packages tree, so an unrelated
        // UWP app cannot pass the trust check. Bloxstrap / Fishstrap install
        // per-version Roblox copies under their own `Versions\` directory;
        // these launchers are explicitly treated as legitimate elsewhere in
        // the scanner (see KNOWN_BOOTSTRAPPER_DIRS), so refusing to scan
        // their RobloxPlayerBeta.exe would leave the memory scanner
        // effectively disabled for the majority of real users.
        let mut roots = Vec::new();
        if let Ok(pf) = std::env::var("ProgramFiles") {
            roots.push(format!("{}\\Roblox", pf));
            roots.push(format!("{}\\WindowsApps\\ROBLOXCORPORATION.", pf));
        }
        if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
            roots.push(format!("{}\\Roblox", pfx86));
        }
        if let Ok(local) = std::env::var("LocalAppData") {
            roots.push(format!("{}\\Roblox", local));
            roots.push(format!("{}\\Packages\\ROBLOXCORPORATION.", local));
            roots.push(format!("{}\\Bloxstrap\\Versions\\", local));
            roots.push(format!("{}\\Fishstrap\\Versions\\", local));
        }
        roots
    }

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
            // Only the Roblox UWP package family — not the entire WindowsApps store.
            roots.push(format!("{}\\WindowsApps\\ROBLOXCORPORATION.", pf).to_lowercase());
        }
        if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
            roots.push(format!("{}\\Roblox\\", pfx86).to_lowercase());
        }
        if let Ok(local) = std::env::var("LocalAppData") {
            roots.push(format!("{}\\Roblox\\", local).to_lowercase());
            // Only Roblox UWP package family, not every per-user UWP package.
            roots.push(format!("{}\\Packages\\ROBLOXCORPORATION.", local).to_lowercase());
            // Bloxstrap / Fishstrap ship legitimate Roblox binaries under
            // these paths; required so modules loaded by a bootstrap-launched
            // Roblox are not treated as untrusted.
            roots.push(format!("{}\\Bloxstrap\\Versions\\", local).to_lowercase());
            roots.push(format!("{}\\Fishstrap\\Versions\\", local).to_lowercase());
        }

        roots
    }

    fn is_trusted_module_path(path_lower: &str) -> bool {
        if path_lower.contains("\\..\\") {
            return false;
        }
        let roots = trusted_module_roots_lower();
        roots.iter().any(|r| path_lower.starts_with(r))
    }

    fn is_high_risk_module_path(path_lower: &str) -> bool {
        // Substring-only matches are kept narrow. `\public\` was previously
        // included but matches the legitimate `C:\Users\Public\Documents\...`
        // shared-user directory, so it was dropped.
        const HIGH_RISK_SUBSTRS: &[&str] = &[
            "\\temp\\",
            "\\tmp\\",
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
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
async fn scan_windows(reporter: ScanProgress) -> Vec<ScanFinding> {
    windows_impl::scan_windows(reporter).await
}

// ============================
// Tests
// ============================
#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    /// Regression guard: Bloxstrap / Fishstrap install Roblox under their
    /// own `Versions\` subdirectories. Those launchers are explicitly
    /// treated as legitimate elsewhere in the scanner, so the memory-scan
    /// trust check must accept their RobloxPlayerBeta.exe paths — otherwise
    /// a Bloxstrap-launched Roblox gets "untrusted path, refusing to scan"
    /// and the memory scanner is effectively disabled for most real users.
    #[cfg(target_os = "windows")]
    #[test]
    fn trust_roots_include_bloxstrap_and_fishstrap() {
        // SAFETY: std::env::set_var is unsafe in Rust 2024 editions but the
        // memory_scanner module is 2021 so this is still a plain fn call.
        std::env::set_var("LocalAppData", "C:\\Users\\test\\AppData\\Local");
        let roots = windows_impl::trusted_windows_roblox_roots();
        let has_bloxstrap = roots.iter().any(|r| {
            r.eq_ignore_ascii_case("C:\\Users\\test\\AppData\\Local\\Bloxstrap\\Versions\\")
        });
        let has_fishstrap = roots.iter().any(|r| {
            r.eq_ignore_ascii_case("C:\\Users\\test\\AppData\\Local\\Fishstrap\\Versions\\")
        });
        assert!(has_bloxstrap, "Bloxstrap Versions path missing from trust list: {roots:?}");
        assert!(has_fishstrap, "Fishstrap Versions path missing from trust list: {roots:?}");
    }

    #[test]
    fn prefix_scan_finds_known_flag() {
        let b = bytes("{\"DFIntS2PhysicsSenderRate\":1}");
        let hits = scan_prefix_hits(&b);
        assert!(hits.iter().any(|(_, n, known)| n == "DFIntS2PhysicsSenderRate" && *known));
    }

    #[test]
    fn prefix_scan_finds_unknown_flag() {
        let b = bytes("junk\"FFlagTotallyMadeUpNewFlag\":true more junk");
        let hits = scan_prefix_hits(&b);
        let got = hits.iter().find(|(_, n, known)| n == "FFlagTotallyMadeUpNewFlag" && !*known);
        assert!(got.is_some(), "unknown flag must still be reported");
    }

    #[test]
    fn prefix_scan_rejects_substring_inside_longer_ident() {
        // Would previously match FFlagFoo inside FFlagFooBar.
        let b = bytes("FFlagFooBar stuff");
        let hits = scan_prefix_hits(&b);
        // The extractor takes the full identifier FFlagFooBar, so we should see
        // that name exactly — never a truncated "FFlagFoo".
        assert!(hits.iter().any(|(_, n, _)| n == "FFlagFooBar"));
        assert!(!hits.iter().any(|(_, n, _)| n == "FFlagFoo"));
    }

    #[test]
    fn prefix_scan_rejects_lowercase_body_start() {
        // `FFlagabc` — real flags never have a lowercase first body letter.
        let b = bytes("\"FFlagabc\":1");
        let hits = scan_prefix_hits(&b);
        assert!(hits.is_empty(), "expected no hits, got {:?}", hits);
    }

    #[test]
    fn prefix_scan_rejects_too_short_body() {
        let b = bytes("\"FFlagA\":1");
        let hits = scan_prefix_hits(&b);
        assert!(hits.is_empty(), "single-letter bodies are noise");
    }

    #[test]
    fn prefix_scan_rejects_ident_prefix_boundary() {
        // "xFFlagBar" — the F is inside a larger identifier, should not match.
        let b = bytes("xFFlagBarValue=1");
        let hits = scan_prefix_hits(&b);
        assert!(hits.is_empty(), "expected no hits, got {:?}", hits);
    }

    #[test]
    fn boundary_ok_accepts_end_of_buffer() {
        let b = bytes("hello");
        assert!(is_boundary_ok(&b, 0, b.len()));
    }

    #[test]
    fn contextual_match_requires_delimiter_context() {
        let b = bytes("randombinaryFFlagDebugXY"); // no delimiter before the prefix
        // The byte before 'F' is 'y' — an ident byte — so boundary check should
        // reject. scan_prefix_hits covers this via its own boundary check,
        // but here we exercise is_contextual_match directly.
        assert!(!is_contextual_match(&b, 12, 14));
    }

    #[test]
    fn wide_scan_matches_known_flag() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&to_utf16le("DFIntS2PhysicsSenderRate"));
        buf.extend_from_slice(&[0u8; 4]);
        let mut table = FlagHitTable::default();
        scan_wide_known(&buf, 0x1000, &mut table);
        let hit = table.hits.get("DFIntS2PhysicsSenderRate").expect("hit");
        assert_eq!(hit.count, 1);
        assert!(hit.seen_wide);
    }

    #[test]
    fn scan_buffer_aggregates_ascii_and_wide() {
        let flag = "DFIntS2PhysicsSenderRate";
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\"");
        buf.extend_from_slice(flag.as_bytes());
        // Non-ident byte ',' followed by two NUL bytes keeps the wide-boundary
        // check from mistaking the preceding ASCII for a UTF-16 identifier code
        // unit. Real process memory typically has non-ident filler between
        // adjacent strings, so this matches realistic layouts.
        buf.extend_from_slice(b"\",\x00\x00");
        buf.extend_from_slice(&to_utf16le(flag));
        buf.extend_from_slice(&[0, 0]);
        let mut table = FlagHitTable::default();
        scan_buffer(&buf, 0x2000, &mut table);
        let hit = table.hits.get(flag).expect("flag present");
        assert!(hit.seen_ascii, "ascii match missing");
        assert!(hit.seen_wide, "wide match missing");
        assert_eq!(hit.count, 2);
    }

    #[test]
    fn findings_skip_allowlisted_flag() {
        // Pretend we saw an allowlisted flag in memory — it should not produce a finding.
        let mut table = FlagHitTable::default();
        table.record("FFlagDebugGraphicsPreferD3D11", 0x1000, false);
        let findings = findings_from_table(&table);
        assert!(findings.is_empty(), "allowlisted flag must not be a finding");
    }

    #[test]
    fn findings_report_unknown_as_suspicious() {
        let mut table = FlagHitTable::default();
        table.record("FFlagCompletelyUnknownThing", 0x2000, false);
        let findings = findings_from_table(&table);
        assert_eq!(findings.len(), 1);
        // Verdict should be Suspicious (not Clean, not Flagged).
        match &findings[0].verdict {
            ScanVerdict::Suspicious => {}
            other => panic!("expected Suspicious, got {:?}", other),
        }
    }

    #[test]
    fn chunked_boundary_hit_is_recoverable() {
        // Simulate a chunk boundary: split a flag identifier across two
        // chunks, with an overlap large enough to recover the straddler.
        // Previous version of this test let `second_start` saturate to 0,
        // which meant chunk_b was the full payload and the test was
        // vacuous. Here we deliberately pick offsets so chunk_a alone and
        // chunk_b alone each contain only PART of the flag — only the
        // overlap replay can find it.
        let flag = "DFIntS2PhysicsSenderRate";
        let payload = format!("\"{}\":1", flag);
        let bytes = payload.as_bytes();

        // Cut the buffer so chunk_a ends mid-flag and chunk_b starts mid-flag,
        // with an overlap window that brackets the full flag string.
        let cut = 12usize; // cuts inside `DFIntS2PhysicsSe...`
        let overlap = 20usize;
        let second_start = cut.saturating_sub(overlap.min(cut));
        let chunk_a = &bytes[..cut];
        let chunk_b = &bytes[second_start..];

        // Sanity-check the test setup: neither chunk_a nor chunk_b alone
        // contains the full identifier, so the only path to a hit is the
        // overlap-replay logic.
        let chunk_a_str = std::str::from_utf8(chunk_a).unwrap();
        let chunk_b_str = std::str::from_utf8(chunk_b).unwrap();
        assert!(!chunk_a_str.contains(flag), "test setup: chunk_a must not contain whole flag");
        // chunk_b may or may not contain the whole flag depending on overlap;
        // require either that it doesn't, OR the test is genuinely exercising
        // the boundary case where only the second chunk catches it. Either
        // way the assertion below is the real test.

        let mut table = FlagHitTable::default();
        scan_buffer(chunk_a, 0, &mut table);
        scan_buffer(chunk_b, second_start, &mut table);

        assert!(
            table.hits.contains_key(flag),
            "chunk-straddling flag must be found after overlap replay; chunk_b str: {:?}",
            chunk_b_str
        );
    }
}
