use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Verdict indicating the severity of a scan finding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Flagged,
}

/// A single finding from a scanner module.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanFinding {
    /// Which scanner module produced this finding.
    pub module: String,
    /// The severity verdict.
    pub verdict: ScanVerdict,
    /// Human-readable description of what was found.
    pub description: String,
    /// Optional extra details (e.g., file path, memory address).
    pub details: Option<String>,
    /// When the finding was recorded.
    pub timestamp: DateTime<Utc>,
}

impl ScanFinding {
    pub fn new(
        module: impl Into<String>,
        verdict: ScanVerdict,
        description: impl Into<String>,
        details: Option<String>,
    ) -> Self {
        // Redact user-home segments in every finding string before it
        // hangs off the ScanFinding. Descriptions rarely include paths,
        // but do occasionally (e.g. process exe paths), and details are
        // where the leakage risk actually lives. Applying here keeps the
        // per-scanner formatters short and guarantees no scanner can
        // accidentally publish the user's real name.
        let description = crate::util::redact_user_paths(&description.into());
        let details = details.map(|d| crate::util::redact_user_paths(&d));
        Self {
            module: module.into(),
            verdict,
            description,
            details,
            timestamp: Utc::now(),
        }
    }
}
