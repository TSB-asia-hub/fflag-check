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
/// Intentionally empty; see the MEMORY_SOFT_FINDINGS list below for the
/// softer-downgrade mechanism the TSB-common flags now use.
pub static MEMORY_BASELINE_FLAGS: &[&str] = &[];

/// TSB-community ambiguous flags. Commonly observed in The Strongest
/// Battlegrounds player memory across both vanilla and modified clients;
/// we can't disambiguate "Roblox-internal registry reference" from
/// "injector wrote this" at the name level. Emit as Suspicious (yellow)
/// rather than the full CRITICAL/HIGH/MEDIUM severity the suspicious_flags
/// database assigns, so tournament staff still see an inspectable row but
/// the overall scan verdict doesn't go red purely from a shared community
/// pattern.
///
/// Only the memory scanner consults this list. If one of these names
/// appears in a local ClientAppSettings.json or bootstrapper config, the
/// client_settings scanner still flags it at full severity — actively
/// writing the value is a real override regardless of how common the name
/// is in heap.
///
/// DFIntS2PhysicsSenderRate is deliberately NOT on this list: it is the
/// canonical desync / fake-lag override and must retain its Flagged
/// severity in memory as well as in config files.
pub static MEMORY_SOFT_FINDINGS: &[&str] = &[
    // ---- Caller-provided "CRITICAL" tier minus DFIntS2PhysicsSenderRate ----
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
    "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier",
    "DFIntTimestepArbiterHumanoidTurningVelThreshold",
    "FFlagProcessAnimationLooped",
    "FFlagRemapAnimationR6ToR15Rig",
    "FFlagSimAdaptiveTimesteppingDefault2",
    // ---- Caller-provided "HIGH" tier ----
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
    // ---- Caller-provided "MEDIUM" tier ----
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

/// True if this flag name is an ambiguous TSB-community memory finding
/// whose severity should be capped at Suspicious when seen in memory.
pub fn is_memory_soft_finding(flag_name: &str) -> bool {
    MEMORY_SOFT_FINDINGS.iter().any(|&f| f == flag_name)
}

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
    fn memory_baseline_stays_empty() {
        // The full-suppression baseline is reserved for future flags that
        // are proven Roblox-internal AND high-volume false positives. The
        // TSB-common list uses MEMORY_SOFT_FINDINGS instead, which fires
        // at Suspicious severity rather than silencing.
        assert!(MEMORY_BASELINE_FLAGS.is_empty());
    }

    #[test]
    fn memory_soft_findings_cover_tsb_sample() {
        // Pin one sample per tier the soft list draws from so a cleanup
        // accidentally removing an entry fails CI.
        assert!(is_memory_soft_finding("DFIntMaxActiveAnimationTracks"));
        assert!(is_memory_soft_finding("FFlagUnifiedLightingBetaFeature"));
        assert!(is_memory_soft_finding("FLogNetwork"));
    }

    #[test]
    fn canonical_desync_flag_stays_at_full_severity() {
        // Non-negotiable: DFIntS2PhysicsSenderRate is the #1 desync /
        // fake-lag override. It must never be silenced (baseline) AND
        // must not be downgraded to Suspicious (soft findings) — keep it
        // out of both lists so memory-only injectors (LornoFix class) are
        // still surfaced at Flagged severity.
        assert!(!MEMORY_BASELINE_FLAGS.contains(&"DFIntS2PhysicsSenderRate"));
        assert!(!is_memory_soft_finding("DFIntS2PhysicsSenderRate"));
    }

    #[test]
    fn memory_soft_findings_do_not_leak_into_official_allowlist() {
        // Never overlap: a flag on Roblox's official allowlist is not a
        // finding at all, so it should never also appear in the soft
        // list.
        for &soft in MEMORY_SOFT_FINDINGS {
            assert!(
                !is_allowed_flag(soft),
                "{} is on Roblox's official allowlist; remove from MEMORY_SOFT_FINDINGS",
                soft
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
