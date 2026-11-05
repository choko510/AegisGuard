//! Honest status vocabulary shared by every screen.
//!
//! A state is always shown with a text label and a glyph, never by color
//! alone. Nothing here can express "protected" or "safe": the best state is
//! `NothingFound`, which still means "only within what was inspected".

/// What a piece of the UI can truthfully say about something.
// Some states are only produced once data views exist (P7-02).
#[allow(dead_code)]
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
    /// Something worth a look (observed / low).
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

/// Visual tone of a status; mapped to colors by the theme.
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

    /// A glyph that also distinguishes the state without color.
    pub fn glyph(self) -> &'static str {
        match self {
            Self::NotAvailable => "―",
            Self::NoData => "？",
            Self::Stale => "⌛",
            Self::Incomplete => "◐",
            Self::NothingFound => "○",
            Self::Observed => "●",
            Self::Review => "▲",
            Self::High => "◆",
            Self::Running => "▶",
            Self::Stopped => "■",
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
    fn every_status_has_a_distinct_label_and_glyph() {
        let mut labels: Vec<_> = ALL.iter().map(|s| s.label()).collect();
        let mut glyphs: Vec<_> = ALL.iter().map(|s| s.glyph()).collect();
        labels.sort_unstable();
        labels.dedup();
        glyphs.sort_unstable();
        glyphs.dedup();
        assert_eq!(labels.len(), ALL.len());
        assert_eq!(glyphs.len(), ALL.len());
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
