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
/// Roblox loads its entire FFlag registry (~20k names) into heap at startup.
/// The mere presence of any of these names as a string in heap is therefore
/// evidence of nothing — Roblox itself put them there. This list covers
/// Roblox-shipped A/B rollout, telemetry, UI modernization, and rendering
/// rollout flags that would otherwise fire on every vanilla client.
///
/// Only the memory scanner consults this list. If any of these names appear
/// in a local ClientAppSettings.json or bootstrapper config with a non-
/// default value, the client_settings scanner still flags them at full
/// severity — actively writing the value is a real override regardless of
/// how common the name is in heap.
///
/// DFIntS2PhysicsSenderRate is deliberately NOT on this list (see the test
/// `canonical_desync_flag_stays_at_full_severity`): it is the canonical
/// memory-only desync override and must retain its Flagged severity.
pub static MEMORY_BASELINE_FLAGS: &[&str] = &[
    // ---- Chrome in-game menu rollout (shipped default on modern clients) ----
    "FFlagEnableInGameMenuChromeABTest2",
    "FFlagEnableInGameMenuChromeABTest4",
    "FFlagEnableIngameMenuChrome",
    "FFlagEnableInGameMenuSongbirdABTest",
    "FFlagEnableChromePinnedChat",
    // ---- Beta badges / cosmetic UI A-B (no gameplay effect) ----
    "FFlagVoiceBetaBadge",
    "FFlagTopBarUseNewBadge",
    "FFlagEnableBetaBadgeLearnMore",
    "FFlagBetaBadgeLearnMoreLinkFormview",
    "FFlagControlBetaBadgeWithGuac",
    "FFlagCoreGuiTypeSelfViewPresent",
    // ---- Roblox-side network rollout toggles (server-controlled) ----
    "FFlagOptimizeNetwork",
    "FFlagOptimizeNetworkRouting",
    "FFlagOptimizeNetworkTransport",
    "FFlagOptimizeServerTickRate",
    // ---- Shipped FPS-cap feature (not an uncap) ----
    "FFlagGameBasicSettingsFramerateCap",
    "FFlagGameBasicSettingsFramerateCap5",
    "FFlagTaskSchedulerLimitTargetFpsTo2402",
    // ---- Shipped rendering feature flags (not cheats on their own) ----
    "FFlagGlobalWindRendering",
    "FFlagGlobalWindActivated",
    "FFlagRenderFixFog",
    "FFlagRenderFixGrassPrepass",
    "FFlagUnifiedLightingBetaFeature",
    "FFlagRenderUnifiedLighting6",
    "FFlagFastGPULightCulling3",
    "FFlagNewLightAttenuation",
    "FFlagRenderNoLowFrmBloom",
    // ---- Bug-fix toggles named "Fix*" (not disable-fix toggles) ----
    "FFlagCommitToGraphicsQualityFix",
    "FFlagFixGraphicsQuality",
    // ---- Built-in user-facing features (Shift-F5 FPS, quick launch, …) ----
    "FFlagDebugDisplayFPS",
    "FFlagEnableQuickGameLaunch",
    "FFlagEnableCommandAutocomplete",
    "FFlagEnableBubbleChatFromChatService",
    // ---- Shipped GUI-hide accessibility API ----
    "FFlagUserShowGuiHideToggles",
    "FFlagGuiHidingApiSupport2",
    "DFIntCanHideGuiGroupId",
    // ---- Server-controlled reconnect kill-switches (client value ignored) ----
    "FFlagReconnectDisabled",
    "FStringReconnectDisabledReason",
    // ---- UIBlox theming (Lua app chrome) ----
    "FFlagLuaAppUseUIBloxColorPalettes1",
    "FFlagUIBloxUseNewThemeColorPalettes",
    // ---- Engine-internal render threading assertions ----
    "FFlagDebugCheckRenderThreading",
    "FFlagRenderDebugCheckThreading2",
    "FFlagRenderCheckThreading",
    "FFlagDebugRenderingSetDeterministic",
    // ---- Ad service toggle (privacy choice, not a cheat) ----
    "FFlagAdServiceEnabled",
    // ---- Telemetry / logging verbosity ----
    "FLogNetwork",
    // ---- Engine-internal debug overlays (developer tools, not ESP) ----
    "FFlagDebugDisplayUnthemedInstances",
    "FFlagDebugLightGridShowChunks",
    "FFlagTrackerLodControllerDebugUI",
    // ---- Internal migration/patching scaffolding ----
    "FFlagDataModelPatcherForceLocal",
    "FFlagRefactorPlayerConnect",
    "FFlagDebugLocalRccServerConnection",
    // ---- Animation system corrections ----
    "FFlagQuaternionPoseCorrection",
    "FFlagRigScaleShouldAffectAnimations",
    // ---- Reporting flow rollout ----
    "FFlagEnableReportAbuseMenuRoactABTest2",
];

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
    // Names that MAY be injector-written OR Roblox-internal — not confident
    // enough either way to silence outright (that's MEMORY_BASELINE_FLAGS)
    // nor flag at full severity. Cap to Suspicious and keep an inspectable
    // row for tournament staff.
    //
    // Entries that have since been proven to be Roblox-shipped registry
    // names were moved to MEMORY_BASELINE_FLAGS; do not re-add them here.
    //
    // ---- Physics / replication engine defaults ----
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
    // ---- Rendering engine defaults ----
    "DFFlagDebugDrawEnable",
    "DFIntPerformanceControlTextureQualityBestUtility",
    "DFIntTextureCompositorActiveJobs",
    "FIntCameraFarZPlane",
    "FIntCameraMaxZoomDistance",
    "FIntMaxCameraMaxZoomDistance",
    "FIntScrollWheelDeltaAmount",
    "FIntTextureCompositorLowResFactor",
    "FStringTerrainMaterialTable2022",
    "FStringTerrainMaterialTablePre2022",
    // ---- Assorted engine internals ----
    "DFFlagOrder66",
    "DFFlagUseVisBugChecks",
    "DFIntCSGv2LodsToGenerate",
    "DFIntDebugSimPhysicsSteppingMethodOverride",
    "DFIntRaknetBandwidthPingSendEveryXSeconds",
    "FIntFullscreenTitleBarTriggerDelayMillis",
    "FIntRuntimeMaxNumOfThreads",
    "FIntTaskSchedulerThreadMin",
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
    fn memory_baseline_covers_known_roblox_shipped_names() {
        // The baseline silences flag names Roblox itself loads into process
        // heap via its runtime flag registry. Without these entries the
        // memory scanner would fire Suspicious/Flagged findings on every
        // vanilla client that has the registry resident (which is every
        // live client, per memory_scanner.rs:582-588). Pin the canonical
        // samples so a cleanup cannot accidentally re-empty the list.
        assert!(is_memory_baseline_flag("FFlagAdServiceEnabled"));
        assert!(is_memory_baseline_flag("FFlagTopBarUseNewBadge"));
        assert!(is_memory_baseline_flag("FFlagEnableInGameMenuChromeABTest4"));
        assert!(is_memory_baseline_flag("FFlagUnifiedLightingBetaFeature"));
        assert!(is_memory_baseline_flag("FFlagGameBasicSettingsFramerateCap5"));
        assert!(is_memory_baseline_flag("FLogNetwork"));
        assert!(is_memory_baseline_flag("FFlagRenderFixFog"));
        assert!(is_memory_baseline_flag("FFlagDebugDisplayFPS"));
    }

    #[test]
    fn memory_soft_findings_cover_tsb_sample() {
        // Pin canonical ambiguous names so a cleanup accidentally removing
        // an entry fails CI. Genuinely-shipped names belong in
        // MEMORY_BASELINE_FLAGS, not here.
        assert!(is_memory_soft_finding("DFIntMaxActiveAnimationTracks"));
        assert!(is_memory_soft_finding("FFlagSimAdaptiveTimesteppingDefault2"));
        assert!(is_memory_soft_finding("DFIntMinimalSimRadiusBuffer"));
    }

    #[test]
    fn memory_soft_and_baseline_are_disjoint() {
        // Baseline silences entirely; soft demotes to Suspicious. A name on
        // both is ambiguous signalling — baseline wins in findings_from_table
        // but the redundancy makes the soft list misleading. Keep them
        // disjoint.
        for &soft in MEMORY_SOFT_FINDINGS {
            assert!(
                !MEMORY_BASELINE_FLAGS.contains(&soft),
                "{} is on both MEMORY_SOFT_FINDINGS and MEMORY_BASELINE_FLAGS; \
                 if it is Roblox-shipped, remove from soft findings — baseline \
                 silences it",
                soft
            );
        }
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
