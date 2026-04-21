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

/// Memory-scan baseline. FFlag NAMES that are present in virtually every
/// real Roblox process because the runtime/game server references them in
/// the internal flag table — the memory scanner finding the string in
/// heap memory is not evidence of a client-side exploit, just that Roblox
/// knows about the flag.
///
/// Critically, this list is NOT consulted by the client_settings scanner.
/// If a player actively writes one of these names into a local
/// ClientAppSettings.json or a bootstrapper config, that is still an
/// override worth surfacing — the desync / physics-manipulation risk
/// attaches to the *value* being set, not the name being mentioned.
///
/// Curated from operator sampling across TSB (The Strongest Battlegrounds)
/// players on 2026-04-21. Names observed on every sampled vanilla client
/// regardless of whether the player was exploiting.
pub static MEMORY_BASELINE_FLAGS: &[&str] = &[
    // ---- Previously CRITICAL tier (17) ----
    "DFIntBulletContactBreakOrthogonalThresholdPercent",
    "DFIntBulletContactBreakThresholdPercent",
    "DFIntDebugDefaultTargetWorldStepsPerFrame",
    "DFIntGameNetLocalSpaceMaxSendIndex",
    "DFIntGameNetPVHeaderRotationalVelocityZeroCutoffExponent",
    "DFIntMaxActiveAnimationTracks",
    "DFIntMaxMissedWorldStepsRemembered",
    "DFIntMinimalSimRadiusBuffer",
    "DFIntPhysicsSenderMaxBandwidthBps",
    "DFIntRaycastMaxDistance",
    "DFIntReplicatorAnimationTrackLimitPerAnimator",
    // DFIntS2PhysicsSenderRate deliberately NOT baselined — it is the
    // canonical desync / fake-lag override, and even seeing the name
    // resident in memory is worth surfacing because a memory-only
    // injector (LornoFix-class) never touches a config file. A small
    // number of vanilla-process false positives is a tolerable cost to
    // keep detection of the #1 flag in the suspicious database.
    "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier",
    "DFIntTimestepArbiterHumanoidTurningVelThreshold",
    "FFlagProcessAnimationLooped",
    "FFlagRemapAnimationR6ToR15Rig",
    "FFlagSimAdaptiveTimesteppingDefault2",
    // ---- Previously HIGH tier (15) ----
    "DFFlagDebugDrawEnable",
    "DFIntCanHideGuiGroupId",
    "DFIntPerformanceControlTextureQualityBestUtility",
    "DFIntTextureCompositorActiveJobs",
    "FFlagDataModelPatcherForceLocal",
    "FFlagGuiHidingApiSupport2",
    "FFlagUnifiedLightingBetaFeature",
    "FFlagUserShowGuiHideToggles",
    "FIntCameraFarZPlane",
    "FIntCameraMaxZoomDistance",
    "FIntMaxCameraMaxZoomDistance",
    "FIntScrollWheelDeltaAmount",
    "FIntTextureCompositorLowResFactor",
    "FStringTerrainMaterialTable2022",
    "FStringTerrainMaterialTablePre2022",
    // ---- Previously MEDIUM tier (22) ----
    "DFFlagOrder66",
    "DFFlagUseVisBugChecks",
    "DFIntCSGv2LodsToGenerate",
    "DFIntDebugSimPhysicsSteppingMethodOverride",
    "DFIntRaknetBandwidthPingSendEveryXSeconds",
    "FFlagAdServiceEnabled",
    "FFlagControlBetaBadgeWithGuac",
    "FFlagEnableBubbleChatFromChatService",
    "FFlagEnableInGameMenuChromeABTest4",
    "FFlagEnableInGameMenuSongbirdABTest",
    "FFlagFastGPULightCulling3",
    "FFlagGameBasicSettingsFramerateCap5",
    "FFlagRenderDebugCheckThreading2",
    "FFlagRenderFixGrassPrepass",
    "FFlagRenderNoLowFrmBloom",
    "FFlagRigScaleShouldAffectAnimations",
    "FFlagTaskSchedulerLimitTargetFpsTo2402",
    "FFlagTopBarUseNewBadge",
    "FIntFullscreenTitleBarTriggerDelayMillis",
    "FIntRuntimeMaxNumOfThreads",
    "FIntTaskSchedulerThreadMin",
    "FLogNetwork",
];

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
    fn memory_baseline_covers_tsb_sample() {
        // Sanity: if anyone re-sorts or accidentally deletes entries from
        // MEMORY_BASELINE_FLAGS, TSB-common flag names start firing again
        // and flood the UI on every vanilla Roblox run. Pin one sample
        // from each of the three tiers the baseline draws from.
        assert!(is_memory_baseline_flag("DFIntMaxActiveAnimationTracks"));
        assert!(is_memory_baseline_flag("FFlagUnifiedLightingBetaFeature"));
        assert!(is_memory_baseline_flag("FLogNetwork"));
    }

    #[test]
    fn canonical_desync_flag_is_not_baselined() {
        // Non-negotiable: DFIntS2PhysicsSenderRate is the #1 desync /
        // fake-lag override. It must NEVER end up in the memory baseline,
        // even as we grow the TSB-common list, because a memory-resident
        // injector (LornoFix-class) only ever touches process memory and
        // this is our only line of defence against it.
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
