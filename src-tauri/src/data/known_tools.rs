/// Known cheat/injection tool process names (lowercase, substring match).
///
/// Curation rules:
/// - Substrings must be specific enough to avoid false positives. `"ida"`
///   would match kindle/nvidia/mediaserver and was removed in favor of the
///   exact filename match `"ida64.exe"` in KNOWN_TOOL_FILENAMES.
/// - Wireshark is widely used by legitimate developers and is intentionally
///   excluded.
/// - Legitimate Roblox launchers (Bloxstrap, Fishstrap, AppleBlox) are NOT
///   listed here — see KNOWN_BOOTSTRAPPER_PROCESS_NAMES below for the
///   informational-tier list. Only Voidstrap (the cheat fork of Bloxstrap)
///   is treated as a tool.
pub static KNOWN_PROCESS_NAMES: &[&str] = &[
    // Roblox-targeted FFlag tooling
    "voidstrap",
    "fflag injector",
    "fflagtoolkit",
    "lornofix",
    "lorno fix",
    // Internal build-target name of LornoFix (see PDB path in binary)
    "odessa",
    "fflag-manager",
    // Roblox executors / DLL frameworks (2026 ecosystem)
    "synapse",
    "krnl",
    "fluxus",
    "hydrogen",
    "wave",
    "solara",
    "krampus",
    "arceus",
    "delta",
    "codex",
    "trigon",
    "electron",
    "valyse",
    "sirhurt",
    "jjsploit",
    "nezur",
    // "swift" was previously listed as a Roblox executor substring but it
    // matches a huge class of legitimate processes — SwiftTunnel (Apple's
    // Network Extension framework used by most macOS VPNs), Swift
    // Playgrounds, swiftformat, swift-build, and so on. Any standalone
    // Swift-branded Roblox tooling should ship with a more specific name
    // under KNOWN_TOOL_FILENAMES instead of a bare three-letter-ish
    // substring.
    "velocity",
    "comet",
    "vega-x",
    "vegax",
    "macsploit",
    "bolt",
    "cryptic",
    "volcano",
    "awp",
    // Generic memory inspection / reverse engineering tools
    "cheatengine",
    "cheat engine",
    "x64dbg",
    "x32dbg",
    "processhacker",
    "process hacker",
    "systeminformer",
    "reclass",
    "reclass.net",
    "hxd",
    "extremeinjector",
    "extreme injector",
    "dll injector",
    "xenos",
    "gh injector",
    "process explorer",
    "ollydbg",
    "windbg",
    "immunity debugger",
    "pe-bear",
    "detect it easy",
    "cff explorer",
    "api monitor",
    "rohitab",
];

/// Known executable filenames for case-insensitive whole-name matching.
pub static KNOWN_TOOL_FILENAMES: &[&str] = &[
    "Voidstrap.exe",
    "CheatEngine.exe",
    "cheatengine-x86_64.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ProcessHacker.exe",
    "SystemInformer.exe",
    "ReClass.NET.exe",
    "HxD.exe",
    "ExtremeInjector.exe",
    "Xenos64.exe",
    "Xenos.exe",
    "GH Injector.exe",
    "ida.exe",
    "ida64.exe",
    "RobloxOffsetDumper.exe",
    "offset_dumper.exe",
    "fflag_injector.exe",
    "LornoFix.exe",
    "odessa.exe",
];

/// Directory names for Roblox-specific FFlag injection / bypass tools. These
/// have no legitimate non-cheat use and warrant a Suspicious verdict.
pub static ROBLOX_CHEAT_DIRS: &[&str] = &[
    "Voidstrap",
    "ExtremeInjector",
    "FFlagToolkit",
    "LornoBypass",
    "fflag-manager",
];

/// Directory names for generic reverse-engineering / debugging tools. These
/// have well-known legitimate uses (CTF, malware analysis, driver debugging,
/// security research) and firing Suspicious on presence alone punishes the
/// entire security community. Recorded as Clean informational notes only.
pub static GENERIC_RE_TOOL_DIRS: &[&str] = &[
    "CheatEngine",
    "Cheat Engine",
    "x64dbg",
    "ProcessHacker",
    "SystemInformer",
    "ReClass.NET",
    "HxD",
];

// Legacy `KNOWN_TOOL_DIRS` constant removed — use `ROBLOX_CHEAT_DIRS` (emit
// Suspicious) or `GENERIC_RE_TOOL_DIRS` (emit Clean informational) directly
// so each call site picks the right severity explicitly.

/// Known tool executable SHA-256 hashes (lowercase hex). Matched even when the
/// binary has been renamed. Keep this list to cross-platform artefacts the
/// scanner is expected to catch in Downloads/Desktop/Documents.
///
/// Entries: (sha256_lowercase_hex, display_name, note).
pub static KNOWN_TOOL_HASHES: &[(&str, &str, &str)] = &[
    (
        "37cfcd6bf1d3001f95229c76e84709efc4fad822babe8e6e7631912cf2027648",
        "LornoFix.exe",
        "LornoBypass FFlag injector (odessa/fflag-manager build) — writes flags to RobloxPlayerBeta via WriteProcessMemory",
    ),
    (
        "ffaae0bf82a93f662071a76c0165f258db99bae2bfc816e18ebb3e1277a0e3bc",
        "LornoBypass.zip",
        "Distribution archive for the LornoBypass FFlag injector",
    ),
];

/// Filenames that, when co-located with a PE executable, indicate that the PE
/// is almost certainly an FFlag injector. LornoFix ships `fflags.json` (the
/// flags to inject) plus `address.json` (the cached singleton offset) next to
/// the binary; the combination is a strong signal even without a hash match.
pub static INJECTOR_SIBLING_CONFIG_FILES: &[&str] = &["fflags.json", "address.json"];

/// Legitimate Roblox launchers — these are NOT cheat tools per Roblox's own
/// policy (https://devforum.roblox.com/t/3640609). Their presence is recorded
/// for context but should not raise verdict severity on its own.
pub static KNOWN_BOOTSTRAPPER_PROCESS_NAMES: &[&str] = &[
    "bloxstrap",
    "fishstrap",
    "appleblox",
];

/// Directories created by legitimate bootstrappers — informational only.
pub static KNOWN_BOOTSTRAPPER_DIRS: &[&str] = &[
    "Bloxstrap",
    "Fishstrap",
    "AppleBlox",
];
