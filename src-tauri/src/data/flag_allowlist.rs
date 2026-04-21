/// The 18 officially allowed FFlags from Roblox's September 29, 2025
/// announcement (https://devforum.roblox.com/t/3966569).
///
/// Cross-checked against the LeventGameing/allowlist community mirror.
/// LAST_VERIFIED: 2026-04-20. If you change anything here, update that
/// date and re-pull from the source.
pub static ALLOWED_FLAGS: &[&str] = &[
    // Geometry / CSG LOD (4 flags) — these use the DFInt prefix; the
    // earlier draft of this file had FInt, which would have allowed the
    // wrong flag name and silently flagged the real one.
    "DFIntCSGLevelOfDetailSwitchingDistance",
    "DFIntCSGLevelOfDetailSwitchingDistanceL12",
    "DFIntCSGLevelOfDetailSwitchingDistanceL23",
    "DFIntCSGLevelOfDetailSwitchingDistanceL34",
    // Rendering (13 flags)
    "DFFlagTextureQualityOverrideEnabled",
    "DFIntTextureQualityOverride",
    "FIntDebugForceMSAASamples",
    "DFFlagDisableDPIScale",
    "FFlagDebugSkyGray",
    "DFFlagDebugPauseVoxelizer",
    "FFlagDebugGraphicsPreferD3D11",
    "FFlagDebugGraphicsPreferVulkan",
    "FFlagDebugGraphicsPreferOpenGL",
    "DFIntDebugFRMQualityLevelOverride",
    "FIntFRMMinGrassDistance",
    "FIntFRMMaxGrassDistance",
    "FIntGrassMovementReducedMotionFactor",
    // UI / Misc (1 flag)
    "FFlagHandleAltEnterFullscreenManually",
];

/// Check if a given flag name is in the official allowlist.
pub fn is_allowed_flag(flag_name: &str) -> bool {
    ALLOWED_FLAGS.iter().any(|&f| f == flag_name)
}

/// Memory-scan baseline: flag names whose mere presence in Roblox process
/// memory is known-not-interesting and should be suppressed from findings.
///
/// HISTORY: an earlier draft here listed ~54 flags sampled from TSB (The
/// Strongest Battlegrounds) players under the assumption that they were
/// Roblox-internal registry entries present on every vanilla client. That
/// was wrong — the shared set was the fingerprint of the TSB community's
/// shared FFlag injector. Baselining them silenced the exact evidence
/// the memory scanner is supposed to surface. The list was removed in
/// v0.4.11.
///
/// The array is kept (empty) instead of deleted so the suppression hook
/// remains available if a future investigation identifies a flag that is
/// genuinely Roblox-internal AND is a high-volume false positive. Any
/// addition here needs a paired justification in the commit message.
///
/// This list is NOT consulted by the client_settings scanner.
pub static MEMORY_BASELINE_FLAGS: &[&str] = &[];

/// True if this flag name is a memory-scanner baseline — i.e. its presence
/// in process memory is not on its own suspicious.
pub fn is_memory_baseline_flag(flag_name: &str) -> bool {
    MEMORY_BASELINE_FLAGS.iter().any(|&f| f == flag_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_size_matches_official_announcement() {
        assert_eq!(
            ALLOWED_FLAGS.len(),
            18,
            "Roblox's September 2025 allowlist published 18 flags; if Roblox \
             updates the list, change this assertion intentionally and bump \
             the LAST_VERIFIED date in the doc comment."
        );
    }

    #[test]
    fn csg_lod_flags_use_dfint_prefix() {
        // The earlier draft used FInt — wrong prefix means real CSG flag
        // settings escape the allowlist short-circuit and get flagged.
        assert!(is_allowed_flag("DFIntCSGLevelOfDetailSwitchingDistance"));
        assert!(!is_allowed_flag("FIntCSGLevelOfDetailSwitchingDistance"));
    }

    #[test]
    fn memory_baseline_is_empty_by_default() {
        // The old ~54-entry TSB baseline was a mistake: the flags sampled
        // as "common across TSB players" were actually the TSB injector's
        // own fingerprint, so baselining them silenced the detector. The
        // array is kept in the module but empty; any future addition has
        // to come with a justification in the commit log (see the
        // MEMORY_BASELINE_FLAGS doc comment).
        assert!(MEMORY_BASELINE_FLAGS.is_empty());
    }

    #[test]
    fn canonical_desync_flag_is_not_baselined() {
        // Non-negotiable: DFIntS2PhysicsSenderRate is the #1 desync /
        // fake-lag override. Even if the baseline grows again, this flag
        // must never be silenced — memory-only injectors (LornoFix class)
        // never touch a config file, so the memory scan is our only line
        // of defence against them.
        assert!(!is_memory_baseline_flag("DFIntS2PhysicsSenderRate"));
    }

    #[test]
    fn memory_baseline_does_not_leak_into_config_allowlist() {
        // MEMORY_BASELINE_FLAGS must NOT be in ALLOWED_FLAGS. The memory
        // baseline suppresses memory-scan noise only — config-file
        // scanning still treats these as real overrides, because a user
        // writing DFIntS2PhysicsSenderRate into a ClientAppSettings.json
        // is an exploit regardless of Roblox also referencing the name.
        for &baseline in MEMORY_BASELINE_FLAGS {
            assert!(
                !is_allowed_flag(baseline),
                "{} must not be in the Roblox official allowlist",
                baseline
            );
        }
    }

    #[test]
    fn known_real_flag_names_are_allowed() {
        for name in [
            "DFFlagTextureQualityOverrideEnabled",
            "FIntDebugForceMSAASamples",
            "FFlagDebugGraphicsPreferOpenGL",
            "FIntGrassMovementReducedMotionFactor",
            "FFlagHandleAltEnterFullscreenManually",
        ] {
            assert!(is_allowed_flag(name), "{} must be allowed", name);
        }
    }
}
