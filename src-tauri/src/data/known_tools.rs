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
    "swift",
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
];

/// Known tool directory names (relative to common installation roots).
pub static KNOWN_TOOL_DIRS: &[&str] = &[
    "Voidstrap",
    "CheatEngine",
    "Cheat Engine",
    "x64dbg",
    "ProcessHacker",
    "SystemInformer",
    "ReClass.NET",
    "HxD",
    "ExtremeInjector",
    "FFlagToolkit",
];

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
