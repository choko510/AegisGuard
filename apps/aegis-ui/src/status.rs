//! Honest status vocabulary shared by every screen.
//!
//! A state is always shown with an icon (Segoe Fluent Icons) *and* a text
//! label, never by color alone. Nothing here can express "protected" or
//! "safe": the best state is `NothingFound`, which only means "nothing
//! matched within what was inspected".

/// Segoe Fluent Icons code points used by the UI.
pub mod icon {
    pub const HOME: &str = "\u{E80F}";
    pub const SCAN: &str = "\u{E721}";
    pub const BROWSER: &str = "\u{E774}";
    pub const REALTIME: &str = "\u{E9D9}";
    pub const NETWORK: &str = "\u{E968}";
    pub const HISTORY: &str = "\u{E81C}";
    pub const SETTINGS: &str = "\u{E713}";
    pub const SHIELD: &str = "\u{EA18}";
    pub const OPEN_FILE: &str = "\u{E8E5}";
    pub const CLOCK: &str = "\u{E823}";
    pub const SENSOR: &str = "\u{E957}";
    pub const DOCUMENT: &str = "\u{E8A5}";
    pub const RULES: &str = "\u{E8F1}";
    pub const INFO: &str = "\u{E946}";
    pub const LOCK: &str = "\u{E72E}";
}

/// What a piece of the UI can truthfully say about something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The feature does not exist in this build.
    NotAvailable,
    /// No data has been loaded or the source has never produced any.
    NoData,
    /// Data exists but is older than its freshness limit.
    Stale,
    /// Part of the input could not be inspected.
    Incomplete,
    /// Inspected completely, nothing matched. Not proof of safety.
    NothingFound,
    /// Something worth noting (observed / low).
    Observed,
    /// Needs review.
    Review,
    /// Strong signal.
    High,
    /// Running/available as reported by its own source.
    Running,
    /// Reported as stopped or disabled by its own source.
    Stopped,
}

/// InfoBar severity of a status; mapped to colors by the theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Info,
    Good,
    Caution,
    Danger,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAvailable => "まだ利用できません",
            Self::NoData => "データなし",
            Self::Stale => "情報が古い",
            Self::Incomplete => "一部未検査",
            Self::NothingFound => "検査範囲で該当なし",
            Self::Observed => "記録あり",
            Self::Review => "要確認",
            Self::High => "強い兆候",
            Self::Running => "稼働中（自己申告）",
            Self::Stopped => "停止中",
        }
    }

    /// Segoe Fluent Icons glyph.
    pub fn icon(self) -> &'static str {
        match self {
            Self::NotAvailable => "\u{E738}", // Remove
            Self::NoData => "\u{E9CE}",       // Unknown
            Self::Stale => "\u{E823}",        // Clock
            Self::Incomplete => "\u{E7BA}",   // Warning
            Self::NothingFound => "\u{E73E}", // CheckMark
            Self::Observed => "\u{E946}",     // Info
            Self::Review => "\u{E7C1}",       // Flag
            Self::High => "\u{EA39}",         // ErrorBadge
            Self::Running => "\u{E768}",      // Play
            Self::Stopped => "\u{E71A}",      // Stop
        }
    }

    pub fn tone(self) -> Tone {
        match self {
            Self::NotAvailable | Self::NoData => Tone::Neutral,
            Self::Stale | Self::Incomplete | Self::Stopped => Tone::Caution,
            Self::NothingFound | Self::Running => Tone::Good,
            Self::Observed => Tone::Info,
            Self::Review | Self::High => Tone::Danger,
        }
    }
}

/// Words the UI must never show: the engine cannot prove any of them.
#[cfg(test)]
pub const FORBIDDEN_CLAIMS: &[&str] =
    &["保護中", "安全です", "未感染", "感染なし", "問題ありません"];

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Status; 10] = [
        Status::NotAvailable,
        Status::NoData,
        Status::Stale,
        Status::Incomplete,
        Status::NothingFound,
        Status::Observed,
        Status::Review,
        Status::High,
        Status::Running,
        Status::Stopped,
    ];

    #[test]
    fn every_status_has_a_distinct_label_and_icon() {
        for f in [Status::label, Status::icon] {
            let mut v: Vec<_> = ALL.iter().map(|s| f(*s)).collect();
            v.sort_unstable();
            v.dedup();
            assert_eq!(v.len(), ALL.len());
        }
    }

    #[test]
    fn no_status_claims_protection_or_safety() {
        for s in ALL {
            for word in FORBIDDEN_CLAIMS {
                assert!(!s.label().contains(word), "{s:?}");
            }
        }
    }

    #[test]
    fn missing_or_partial_information_is_never_good() {
        for s in [
            Status::NotAvailable,
            Status::NoData,
            Status::Stale,
            Status::Incomplete,
        ] {
            assert_ne!(s.tone(), Tone::Good, "{s:?}");
        }
    }
}
