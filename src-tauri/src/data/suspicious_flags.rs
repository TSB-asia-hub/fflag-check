use crate::models::ScanVerdict;

// =============================================================================
// CRITICAL FLAGS: Desync / Physics / Replication manipulation
// These flags give direct competitive advantage through physics desync,
// teleportation, invisibility, noclip, or simulation radius abuse.
// Sources: Roblox DevForum bug reports, pixelyloaf abusive flags,
// alexbomb6666/rblxflags, fantaize.net desync analysis, community repos.
// =============================================================================
pub static CRITICAL_FLAGS: &[&str] = &[
    // ---- Physics sender rate manipulation (desync / fake-lag) ----
    // Controls how often physics data is sent to server. Value 1 = freeze
    // server-side position; -30 = lock to origin (invisible).
    "DFIntS2PhysicsSenderRate",
    // Typo variant that also appears in community configs
    "DFIntS2PhysicSenderRate",
    // Bandwidth cap for physics replication; 1 = starve server of updates
    "DFIntPhysicsSenderMaxBandwidthBps",
    // Scaling factor for physics sender bandwidth
    "DFIntPhysicsSenderMaxBandwidthBpsScaling",
    // Data sender rate; -1 = block all data replication
    "DFIntDataSenderRate",
    // Touch sender bandwidth; -1 = block touch replication
    "DFIntTouchSenderMaxBandwidthBps",

    // ---- Simulation radius expansion (network ownership theft) ----
    // Expanding sim radius lets client claim ownership of remote parts
    "DFIntMinClientSimulationRadius",
    "DFIntMinimalSimRadiusBuffer",
    "DFIntMaxClientSimulationRadius",
    // Prevent sim radius from shrinking back
    "DFFlagDebugPhysicsSenderDoesNotShrinkSimRadius",
    // Force custom sim radius
    "FFlagDebugUseCustomSimRadius",

    // ---- NextGen Replicator / Aurora desync (invisibility exploit) ----
    // Toggling these breaks character replication on other clients
    "NextGenReplicatorEnabledWrite4",
    "NextGenReplicatorEnabledRead",
    // Large replicator variants used in desync chains
    "LargeReplicatorEnabled9",
    "LargeReplicatorSerializeWrite4",
    "LargeReplicatorSerializeRead3",
    "LargeReplicatorWrite5",
    "LargeReplicatorRead5",
    // Replicator-related network manipulation
    "DFIntReplicatorClusterPacketLimit",
    "DFIntReplicatorWritePacketLimit",

    // ---- Replicator animation track limit (animation desync) ----
    // -1 = disable animation replication; others see no movement
    "DFIntReplicatorAnimationTrackLimitPerAnimator",

    // ---- Game network PV header manipulation (invisibility) ----
    // High exponent zeros out position/velocity headers
    "DFIntGameNetPVHeaderTranslationZeroCutoffExponent",
    "DFIntGameNetPVHeaderLinearVelocityZeroCutoffExponent",
    "DFIntGameNetPVHeaderRotationalVelocityZeroCutoffExponent",

    // ---- Noclip / collision bypass ----
    // Shrinks assembly collision extents; negative = pass through walls
    "DFIntAssemblyExtentsExpansionStudHundredth",
    // Limits broad-phase collision pair count; low value = noclip
    "DFIntSimBroadPhasePairCountMax",
    // Primal solver manipulation for noclip/physics bypass
    "FFlagDebugSimDefaultPrimalSolver",
    "DFIntDebugSimPrimalStiffness",
    "DFIntMaximumFreefallMoveTimeInTenths",

    // ---- Physics engine gravity / force manipulation ----
    // Extreme values cause flying, super-jump, moon gravity
    "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier",
    "DFIntSolidFloorPercentForceApplication",
    "DFIntNonSolidFloorPercentForceApplication",
    "DFIntNewRunningBaseGravityReductionFactorHundredth",
    "DFIntMaxAltitudePDStickHipHeightPercent",
    "DFIntMaximumUnstickForceInGs",
    "DFIntUnstickForceAttackInTenths",
    "DFIntPhysicsDecompForceUpgradeVersion",

    // ---- Simulation timestep manipulation ----
    "FFlagSimAdaptiveTimesteppingDefault2",
    "DFFlagSimHumanoidTimestepModelUpdate",
    "DFIntSimExplicitlyCappedTimestepMultiplier",
    "DFIntMaxTimestepMultiplierAcceleration",
    "DFIntMaxTimestepMultiplierBuoyancy",
    "DFIntMaxTimestepMultiplierContstraint",
    "DFIntTimestepArbiterVelocityCriteriaThresholdTwoDt",
    "DFIntTimestepArbiterHumanoidTurningVelThreshold",
    "DFIntTimestepArbiterOmegaThou",

    // ---- Primal solver gravity / flight exploits ----
    "DFIntDebugSimPrimalLineSearch",
    "DFIntDebugSimPrimalPreconditioner",
    "DFIntDebugSimPrimalNewtonIts",
    "DFIntDebugSimPrimalWarmstartVelocity",
    "DFIntDebugSimPrimalWarmstartForce",
    "FFlagDebugSimPrimalGSLump",
    "FIntDebugSimPrimalGSLumpAlpha",

    // ---- Bullet / contact threshold manipulation ----
    "DFIntBulletContactBreakOrthogonalThresholdPercent",
    "DFIntBulletContactBreakThresholdPercent",

    // ---- Tool desync ----
    "DFIntSimBlockLargeLocalToolWeldManipulationsThreshold",

    // ---- Hip height / animation exploits ----
    "DFIntHipHeightClamp",
    "FFlagRemapAnimationR6ToR15Rig",
    "DFFlagAnimatorPostProcessIK",

    // ---- Physics throttle bypass ----
    "DFIntPhysicsImprovedCyclicExecutiveThrottleThresholdTenth",
    "DFFlagPhysicsSkipNonRealTimeHumanoidForceCalc2",

    // ---- Game network local space manipulation ----
    "DFIntGameNetLocalSpaceMaxSendIndex",

    // ---- Parallel dynamics manipulation ----
    // -1 = invisibility through broken cluster batching
    "FIntParallelDynamicPartsFastClusterBatchSize",

    // ---- Raycast distance manipulation ----
    // Very low = break hit detection; very high = server-side advantage
    "DFIntRaycastMaxDistance",

    // ---- World step / missed step manipulation ----
    "DFIntMaxMissedWorldStepsRemembered",
    "DFIntWorldStepMax",
    "DFIntDebugDefaultTargetWorldStepsPerFrame",

    // ---- Data packet / bandwidth manipulation ----
    "DFIntMaxDataPacketPerSend",
    "DFIntServerMaxBandwith",
    "DFIntAngularVelocityLimit",

    // ---- Max active animation tracks (animation freeze) ----
    "DFIntMaxActiveAnimationTracks",
    "FFlagProcessAnimationLooped",

    // ---- Interpolation manipulation (desync-adjacent) ----
    "DFIntInterpolationFrameVelocityThresholdMillionth",
    "DFIntInterpolationFrameRotVelocityThresholdMillionth",
    "DFIntInterpolationFramePositionThresholdMillionth",
    "DFIntCheckPVDifferencesForInterpolationMinVelThresholdStudsPerSecHundredth",
    "DFIntCheckPVDifferencesForInterpolationMinRotVelThresholdRadsPerSecHundredth",
    "DFIntCheckPVCachedVelThresholdPercent",
    "DFIntCheckPVCachedRotVelThresholdPercent",
    "DFIntCheckPVLinearVelocityIntegrateVsDeltaPositionThresholdPercent",
    "DFIntGameNetDontSendRedundantNumTimes",
    "DFIntGameNetDontSendRedundantDeltaPositionMillionth",

    // ---- Replication focus / NOU manipulation ----
    "DFIntReplicationFocusNouExtentsSizeCutoffForPauseStuds",
    "DFIntSimOwnedNOUCountThresholdMillionth",
    "DFIntStreamJobNOUVolumeCap",
    "DFIntStreamJobNOUVolumeLengthCap",

    // ---- Max acceptable update delay (desync window) ----
    "DFIntMaxAcceptableUpdateDelay",

    // ---- Debug send distance manipulation ----
    "DFIntDebugSendDistInSteps",

    // ---- Solver state replication ----
    "DFFlagSolverStateReplicatedOnly2",

    // ---- Failsafe humanoid (bypass safety checks) ----
    "FFlagFailsafeHumanoid_3",

    // ---- Server connection manipulation ----
    "FFlagDebugLocalRccServerConnection",
    "FFlagRefactorPlayerConnect",
];

// =============================================================================
// HIGH FLAGS: Visual / rendering advantages
// Wallhacks, ESP, x-ray, fog removal, camera manipulation, GUI hiding,
// entity highlighting, and texture stripping that provide visual advantage.
// =============================================================================
pub static HIGH_FLAGS: &[&str] = &[
    // ---- Wallhack / ESP via debug drawing ----
    // Draws outlines around every part and humanoid (wallhack)
    "DFFlagDebugDrawBroadPhaseAABBs",
    // Draws outlines around every body part (ESP through walls)
    "DFFlagDebugDrawBvhNodes",
    // Skeleton rendering through walls (ESP)
    "DFFlagAnimatorDrawSkeletonAttachments",
    "DFFlagAnimatorDrawSkeletonAll",
    "DFIntAnimatorDrawSkeletonScalePercent",
    // Debug draw master enable
    "DFFlagDebugDrawEnable",
    // Humanoid debug rendering (shows collision info through walls)
    "FFlagDebugHumanoidRendering",
    // Highlight outlines (can be abused for ESP on mobile)
    "FFlagHighlightOutlinesOnMobile",

    // ---- X-ray / fog / see-through ----
    // Far Z plane = 1 creates x-ray camera (see through terrain/parts)
    "FIntCameraFarZPlane",
    // Restrict GC distance = 1 makes most geometry invisible
    "DFIntDebugRestrictGCDistance",

    // ---- Camera manipulation (zoom/FOV advantage) ----
    // Extreme zoom distance gives sniper-like view in close-quarters games
    "FIntCameraMaxZoomDistance",
    "FIntMaxCameraMaxZoomDistance",

    // ---- Animation LOD manipulation (see players at all distances) ----
    // 0 = animations always render at full detail regardless of distance
    "DFIntAnimationLodFacsDistanceMin",
    "DFIntAnimationLodFacsDistanceMax",
    "DFIntAnimationLodFacsVisibilityDenominator",

    // ---- Texture removal / stripping (see through surfaces) ----
    // Override texture quality to minimum
    "DFFlagTextureQualityOverrideEnabled",
    "DFIntTextureQualityOverride",
    // Skip mip levels (reduce textures to near-invisible)
    "FIntDebugTextureManagerSkipMips",
    // Remove part textures entirely
    "FStringPartTexturePackTable2022",
    "FStringPartTexturePackTablePre2022",
    // Remove terrain textures (see through terrain)
    "FStringTerrainMaterialTable2022",
    "FStringTerrainMaterialTablePre2022",
    // Texture compositor; 0 = no texture compositing
    "DFIntTextureCompositorActiveJobs",
    "DFIntPerformanceControlTextureQualityBestUtility",
    "FIntTextureCompositorLowResFactor",
    // Terrain slice size manipulation
    "FIntTerrainArraySliceSize",

    // ---- Shadow / lighting removal (see in dark areas) ----
    // 0 = no shadows, full visibility in dark areas
    "FIntRenderShadowIntensity",
    // Disable shadow map culling (also strips shadows)
    "DFIntCullFactorPixelThresholdShadowMapHighQuality",
    "DFIntCullFactorPixelThresholdShadowMapLowQuality",
    // Shadow bias manipulation
    "FIntRenderShadowmapBias",
    // CSG voxelizer fade radius; 0 = no baked shadow fade
    "FIntCSGVoxelizerFadeRadius",

    // ---- Force lighting technology (reduce visual clutter) ----
    "DFFlagDebugRenderForceTechnologyVoxel",
    "FFlagDebugForceFutureIsBrightPhase2",
    "FFlagDebugForceFutureIsBrightPhase3",
    // Unified lighting manipulation
    "FFlagRenderUnifiedLighting6",
    "FFlagUnifiedLightingBetaFeature",

    // ---- Post-processing / fog / wind removal ----
    "FFlagDisablePostFx",
    "FFlagGlobalWindRendering",
    "FFlagGlobalWindActivated",
    "FFlagRenderFixFog",

    // ---- GUI hiding for competitive advantage ----
    "FFlagUserShowGuiHideToggles",
    "FFlagGuiHidingApiSupport2",
    "DFIntCanHideGuiGroupId",
    // Dont render screen GUI (hide all UI overlays)
    "FFlagDebugDontRenderScreenGui",
    "FFlagDebugDontRenderUI",

    // ---- Roughness manipulation (shiny avatars = easier to spot) ----
    "DFIntRenderClampRoughnessMax",

    // ---- Interpolation visualizer (network position debug overlay) ----
    "DFFlagDebugEnableInterpolationVisualizer",

    // ---- Debug display overlays ----
    "FFlagDebugDisplayUnthemedInstances",
    "FFlagDebugLightGridShowChunks",
    "FFlagTrackerLodControllerDebugUI",

    // ---- Particle / sky / visual stripping ----
    "FFlagDebugSkyGray",
    "FFlagDebugDeterministicParticles",
    "DFFlagDebugPauseVoxelizer",

    // ---- SSAO manipulation ----
    "FFlagDebugSSAOForce",
    "FIntSSAOMipLevels",

    // ---- Grass stripping beyond allowlist values ----
    "FIntRenderGrassDetailStrands",
    "FIntRenderGrassHeightScaler",
    "FIntFRMMinGrassDistance",
    "FIntFRMMaxGrassDistance",
    "FIntGrassMovementReducedMotionFactor",

    // ---- Viewport manipulation ----
    "FIntViewportFrameMaxSize",

    // ---- Refactor mesh materials (strip materials) ----
    "FFlagMSRefactor5",

    // ---- Chat / voice chat manipulation for advantage ----
    "FFlagDebugForceChatDisabled",
    "DFIntMaxLoadableAudioChannelCount",
    "DFIntVoiceChatRollOffMinDistance",
    "DFIntVoiceChatRollOffMaxDistance",
    "DFIntVoiceChatVolumeThousandths",
    "DFIntAvatarFaceChatHeadRollLimitDegrees",
    "FFlagDebugDefaultChannelStartMuted",

    // ---- Scroll wheel delta (exploit zoom speed) ----
    "FIntScrollWheelDeltaAmount",

    // ---- Remote event size limit manipulation ----
    "DFIntRemoteEventSingleInvocationSizeLimit",

    // ---- Disconnect / reconnect manipulation ----
    "DFFlagDebugDisableTimeoutDisconnect",
    "FFlagReconnectDisabled",
    "FStringReconnectDisabledReason",

    // ---- Force data model patching ----
    "FFlagDataModelPatcherForceLocal",
];

// =============================================================================
// MEDIUM FLAGS: Moderate advantage
// FPS uncapping, telemetry disabling, network optimization, rendering
// performance flags that also reduce visual clutter, UI manipulation.
// =============================================================================
pub static MEDIUM_FLAGS: &[&str] = &[
    // ---- FPS uncapping / task scheduler manipulation ----
    "DFIntTaskSchedulerTargetFps",
    "FFlagTaskSchedulerLimitTargetFpsTo2402",
    "FFlagGameBasicSettingsFramerateCap",
    "FFlagGameBasicSettingsFramerateCap5",
    "FIntTargetRefreshRate",
    "FIntRefreshRateLowerBound",

    // ---- Telemetry disabling (hides client modifications) ----
    "FFlagDebugDisableTelemetryEphemeralCounter",
    "FFlagDebugDisableTelemetryEphemeralStat",
    "FFlagDebugDisableTelemetryEventIngest",
    "FFlagDebugDisableTelemetryPoint",
    "FFlagDebugDisableTelemetryV2Counter",
    "FFlagDebugDisableTelemetryV2Event",
    "FFlagDebugDisableTelemetryV2Stat",

    // ---- Ad service disabling ----
    "FFlagAdServiceEnabled",

    // ---- Network optimization (potential desync at extreme values) ----
    "FFlagOptimizeNetwork",
    "FFlagOptimizeNetworkRouting",
    "FFlagOptimizeNetworkTransport",
    "FFlagOptimizeServerTickRate",
    "DFIntConnectionMTUSize",
    "DFIntNetworkLatencyTolerance",
    "DFIntNetworkPrediction",
    "DFIntRakNetResendRttMultiple",
    "DFIntRakNetResendTimeoutMS",
    "DFIntRakNetResendBufferArrayLength",
    "DFIntRaknetBandwidthPingSendEveryXSeconds",
    "DFIntRakNetLoopMs",
    "DFIntServerPhysicsUpdateRate",
    "DFIntServerTickRate",
    "FLogNetwork",

    // ---- Graphics quality override ----
    "DFIntDebugFRMQualityLevelOverride",
    "FIntRomarkStartWithGraphicQualityLevel",
    "FFlagCommitToGraphicsQualityFix",
    "FFlagFixGraphicsQuality",

    // ---- Light update frequency reduction ----
    "FIntRenderLocalLightUpdatesMax",
    "FIntRenderLocalLightUpdatesMin",
    "FIntRenderLocalLightFadeInMs",

    // ---- New light attenuation ----
    "FFlagNewLightAttenuation",

    // ---- CSG LOD switching (allowlisted but abusable with extreme values) ----
    "DFIntCSGLevelOfDetailSwitchingDistance",
    "DFIntCSGLevelOfDetailSwitchingDistanceL12",
    "DFIntCSGLevelOfDetailSwitchingDistanceL23",
    "DFIntCSGLevelOfDetailSwitchingDistanceL34",
    "DFIntCSGv2LodsToGenerate",

    // ---- Frame buffer manipulation ----
    "DFIntMaxFrameBufferSize",

    // ---- MSAA manipulation ----
    "FIntDebugForceMSAASamples",

    // ---- Threading manipulation ----
    "FIntRuntimeMaxNumOfThreads",
    "FIntTaskSchedulerThreadMin",

    // ---- Rendering threading checks ----
    "FFlagDebugCheckRenderThreading",
    "FFlagRenderDebugCheckThreading2",
    "FFlagRenderCheckThreading",
    "FFlagDebugRenderingSetDeterministic",

    // ---- DPI scale manipulation ----
    "DFFlagDisableDPIScale",

    // ---- UI manipulation ----
    "FFlagEnableInGameMenuChromeABTest2",
    "FFlagEnableInGameMenuChromeABTest4",
    "FFlagEnableIngameMenuChrome",
    "FFlagEnableInGameMenuSongbirdABTest",
    "FFlagEnableChromePinnedChat",
    "FFlagEnableBubbleChatFromChatService",
    "FFlagCoreGuiTypeSelfViewPresent",
    "FIntFullscreenTitleBarTriggerDelayMillis",
    "FIntFontSizePadding",
    "FIntRobloxGuiBlurIntensity",

    // ---- Badge / UI element hiding ----
    "FFlagVoiceBetaBadge",
    "FFlagTopBarUseNewBadge",
    "FFlagEnableBetaBadgeLearnMore",
    "FFlagBetaBadgeLearnMoreLinkFormview",
    "FFlagControlBetaBadgeWithGuac",
    "FStringVoiceBetaBadgeLearnMoreLink",
    "FStringTopBarBadgeLearnMoreLink",

    // ---- Report abuse menu manipulation ----
    "FStringReportAbuseMenuRoactForcedUserIds",
    "FFlagEnableReportAbuseMenuRoactABTest2",
    "FFlagEnableReportAbuseMenuRoact2",
    "FFlagEnableReportAbuseMenuLayerOnV3",

    // ---- Display FPS overlay ----
    "FFlagDebugDisplayFPS",

    // ---- Debug flag state display ----
    "FStringDebugShowFlagState",

    // ---- DFIntDebugSimPhysicsSteppingMethodOverride ----
    "DFIntDebugSimPhysicsSteppingMethodOverride",

    // ---- Render distance culling ----
    "FFlagRenderTestEnableDistanceCulling",
    "DFFlagDebugSkipMeshVoxelizer",

    // ---- Sound physics velocity ----
    "FFlagSoundsUsePhysicalVelocity",

    // ---- Shadow atlas manipulation ----
    "FIntRenderMaxShadowAtlasUsageBeforeDownscale",

    // ---- Voice chat configuration ----
    "DFIntVoiceChatMaxRecordedDataDeliveryIntervalMs",

    // ---- Modernization forced user IDs ----
    "FStringInGameMenuModernizationStickyBarForcedUserIds",

    // ---- Order66 (misc debug flag) ----
    "DFFlagOrder66",

    // ---- Quaternion / animation override ----
    "FFlagQuaternionPoseCorrection",
    "FFlagRigScaleShouldAffectAnimations",

    // ---- Avatar chat visualization ----
    "FFlagDebugAvatarChatVisualization",

    // ---- GPU light culling ----
    "FFlagFastGPULightCulling3",

    // ---- Deferred lighting disable ----
    "FFlagDebugDisableDeferredLighting",

    // ---- Lua color palettes (UI theming) ----
    "FFlagLuaAppUseUIBloxColorPalettes1",
    "FFlagUIBloxUseNewThemeColorPalettes",

    // ---- Render bloom removal ----
    "FFlagRenderNoLowFrmBloom",

    // ---- Vis bug checks (can affect rendering) ----
    "DFFlagUseVisBugChecks",
    "FFlagEnableVisBugChecks27",
    "FFlagVisBugChecksThreadYield",
    "FIntEnableVisBugChecksHundredthPercent27",

    // ---- Quick game launch ----
    "FFlagEnableQuickGameLaunch",

    // ---- Command autocomplete ----
    "FFlagEnableCommandAutocomplete",

    // ---- Grass render fix ----
    "FFlagRenderFixGrassPrepass",

    // ---- Camera input type manipulation ----
    "FFlagUserCameraControlLastInputTypeUpdate",

    // ---- Debug heap dump ----
    "FFlagDebugLuaHeapDump",
];

// =============================================================================
// LOW FLAGS: Benign / cosmetic but non-allowlisted
// Graphics API preferences, minor rendering tweaks, quality-of-life flags.
// These are unlikely to give competitive advantage but are still non-allowlisted.
// =============================================================================
pub static LOW_FLAGS: &[&str] = &[
    // ---- Graphics API preferences (beyond allowlisted set) ----
    "FFlagDebugGraphicsDisableDirect3D11",
    "FFlagDebugGraphicsPreferOpenGL",
    "FFlagDebugGraphicsPreferD3D11FL10",
    "FFlagDebugGraphicsPreferD3D11",
    "FFlagDebugGraphicsPreferMetal",
    "FFlagGraphicsEnableD3D10Compute",
    "FFlagDebugGraphicsDisableVulkan",
    "FFlagDebugGraphicsDisableVulkan11",
    "FFlagRenderVulkanFixMinimizeWindow",

    // ---- Fullscreen handling (allowlisted but listed for completeness) ----
    "FFlagHandleAltEnterFullscreenManually",

    // ---- Grass reduced motion (allowlisted) ----
    "FFlagGrassReducedMotion",

    // ---- Compression ----
    "DFFlagEnableRequestAsyncCompression",
];

/// Get the severity verdict for a given flag name.
///
/// Returns:
/// - `Flagged` for CRITICAL flags (physics desync, replication manipulation,
///   noclip, simulation radius abuse, gravity exploits).
/// - `Suspicious` for HIGH flags (wallhack, ESP, x-ray, camera abuse,
///   texture stripping, GUI hiding) and MEDIUM flags (FPS uncapping,
///   telemetry disabling, network optimisation, UI manipulation).
/// - `Clean` for LOW flags (benign cosmetic / graphics API preferences)
///   and any flag not in our database.
pub fn get_flag_severity(flag_name: &str) -> ScanVerdict {
    if CRITICAL_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Flagged;
    }
    if HIGH_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Suspicious;
    }
    if MEDIUM_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Suspicious;
    }
    // LOW flags are benign; return Clean.
    ScanVerdict::Clean
}

/// Return a human-readable category label for a flag, or None if unknown.
pub fn get_flag_category(flag_name: &str) -> Option<&'static str> {
    if CRITICAL_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("CRITICAL");
    }
    if HIGH_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("HIGH");
    }
    if MEDIUM_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("MEDIUM");
    }
    if LOW_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("LOW");
    }
    None
}

/// Return a brief description of why a flag is suspicious.
pub fn get_flag_description(flag_name: &str) -> Option<&'static str> {
    match flag_name {
        // === CRITICAL: Physics / Desync ===
        "DFIntS2PhysicsSenderRate" => Some("Physics sender rate: controls how often physics data reaches the server. Exploit values (1, -30, 30000) cause desync/invisibility."),
        "DFIntS2PhysicSenderRate" => Some("Typo variant of physics sender rate; same desync effect."),
        "DFIntPhysicsSenderMaxBandwidthBps" => Some("Caps physics replication bandwidth. Value 1 starves server of position updates."),
        "DFIntPhysicsSenderMaxBandwidthBpsScaling" => Some("Scaling factor for physics sender bandwidth; 0 disables scaling."),
        "DFIntDataSenderRate" => Some("Controls data replication rate. Value -1 blocks all data replication."),
        "DFIntTouchSenderMaxBandwidthBps" => Some("Touch event bandwidth cap. Value -1 blocks touch replication."),
        "DFIntMinClientSimulationRadius" => Some("Minimum client simulation radius. Value 2147000000 claims ownership of all objects."),
        "DFIntMinimalSimRadiusBuffer" => Some("Simulation radius buffer. Extreme values expand network ownership."),
        "DFIntMaxClientSimulationRadius" => Some("Maximum client simulation radius. Value 2147000000 for total map control."),
        "DFFlagDebugPhysicsSenderDoesNotShrinkSimRadius" => Some("Prevents simulation radius from shrinking after expansion."),
        "FFlagDebugUseCustomSimRadius" => Some("Forces custom simulation radius, bypassing server limits."),
        "NextGenReplicatorEnabledWrite4" => Some("NextGen replicator toggle. Rapid toggling causes invisibility desync."),
        "DFIntReplicatorAnimationTrackLimitPerAnimator" => Some("Animation track replication limit. Value -1 hides all animations from other players."),
        "DFIntGameNetPVHeaderTranslationZeroCutoffExponent" => Some("Position header zero cutoff. Value 10 zeros out position data, causing invisibility."),
        "DFIntAssemblyExtentsExpansionStudHundredth" => Some("Assembly collision extents. Value -50 shrinks hitbox, enabling noclip."),
        "DFIntSimBroadPhasePairCountMax" => Some("Broad-phase collision pair limit. Low values disable collision detection (noclip)."),
        "FFlagDebugSimDefaultPrimalSolver" => Some("Enables primal solver. Combined with stiffness=0, enables noclip/flying."),
        "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier" => Some("PD controller substep multiplier. Value -999999 causes extreme gravity manipulation."),
        "DFIntSolidFloorPercentForceApplication" => Some("Solid floor force. Value -1000 causes character to fly/phase through floors."),
        "DFIntNonSolidFloorPercentForceApplication" => Some("Non-solid floor force. Value -5000 causes extreme floor phasing."),
        "FFlagSimAdaptiveTimesteppingDefault2" => Some("Adaptive timestepping. Enables jump height/gravity exploit chain."),
        "DFFlagSimHumanoidTimestepModelUpdate" => Some("Humanoid timestep model update. Part of gravity manipulation chain."),
        "DFIntHipHeightClamp" => Some("Hip height clamp. Value -48 moves character below ground."),
        "FFlagRemapAnimationR6ToR15Rig" => Some("R6 to R15 animation remap. Causes visual desync in animation display."),
        "FIntParallelDynamicPartsFastClusterBatchSize" => Some("Cluster batch size. Value -1 causes invisibility through broken batching."),
        "DFIntRaycastMaxDistance" => Some("Raycast max distance. Value 3 breaks hit detection systems."),
        "DFIntMaxMissedWorldStepsRemembered" => Some("Missed world steps buffer. Value 1000 extends desync window."),
        "DFIntSimBlockLargeLocalToolWeldManipulationsThreshold" => Some("Tool weld threshold. Value -1 enables tool desync exploit."),
        "DFIntMaxActiveAnimationTracks" => Some("Max active animation tracks. Value 0 freezes all animations."),
        "DFIntDebugSimPrimalLineSearch" => Some("Primal solver line search. Various values cause gravity/flight exploits."),
        "DFIntDebugSimPrimalStiffness" => Some("Primal solver stiffness. Value 0 disables physics constraints (noclip)."),

        // === HIGH: Visual Advantage ===
        "DFFlagDebugDrawBroadPhaseAABBs" => Some("Draws outlines around every part/humanoid. Functions as wallhack."),
        "DFFlagDebugDrawBvhNodes" => Some("Draws outlines around body parts. Functions as ESP through walls."),
        "DFFlagAnimatorDrawSkeletonAttachments" => Some("Renders skeleton attachments visible through walls (ESP)."),
        "DFFlagAnimatorDrawSkeletonAll" => Some("Renders full skeleton on all avatars through walls (ESP)."),
        "FFlagDebugHumanoidRendering" => Some("Shows humanoid collision debug info through walls."),
        "FIntCameraFarZPlane" => Some("Camera far Z plane. Value 1 creates x-ray vision effect."),
        "FIntCameraMaxZoomDistance" => Some("Camera max zoom. Value 9999+ gives extreme zoom-out advantage."),
        "DFIntDebugRestrictGCDistance" => Some("Garbage collection distance. Value 1 makes most geometry invisible."),
        "DFIntAnimationLodFacsDistanceMin" => Some("Animation LOD min distance. Value 0 renders all player animations at max detail."),
        "DFIntAnimationLodFacsDistanceMax" => Some("Animation LOD max distance. Value 0 forces full animation detail at all distances."),
        "FIntRenderShadowIntensity" => Some("Shadow intensity. Value 0 removes all shadows for visibility in dark areas."),
        "FFlagDisablePostFx" => Some("Disables post-processing effects. Removes fog, bloom, and visual obstruction."),
        "FFlagDebugDontRenderScreenGui" => Some("Hides all screen GUIs. Can remove game UI for cleaner competitive view."),
        "DFIntRenderClampRoughnessMax" => Some("Roughness clamp. Extreme negative values make avatars extremely shiny/visible."),
        "DFFlagDebugEnableInterpolationVisualizer" => Some("Shows network position debug overlay. Reveals player interpolation data."),

        // === MEDIUM ===
        "DFIntTaskSchedulerTargetFps" => Some("FPS target. Values like 9999 or 2147483647 uncap framerate."),
        "FFlagDebugDisableTelemetryEphemeralCounter" => Some("Disables telemetry counter. Hides client modification from Roblox analytics."),
        "FFlagAdServiceEnabled" => Some("Ad service toggle. Set to false to disable ads."),
        "DFIntConnectionMTUSize" => Some("Network MTU size. Non-default values affect packet fragmentation."),

        _ => None,
    }
}
