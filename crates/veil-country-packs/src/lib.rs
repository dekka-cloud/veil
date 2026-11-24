//! Country packs. Each pack holds its data files under `country-packs/<id>/` and the
//! detectors that read them, versioned apart from the engine.

mod context;
pub mod gh;

use veil_core::Registry;

/// The packs this build ships, by ISO 3166-1 alpha-2 code.
pub const PACKS: &[&str] = &["GH"];

/// Registers every detector in a pack. Unknown packs are refused.
pub fn register(code: &str, registry: &mut Registry) -> Result<(), PackError> {
    match code.to_ascii_uppercase().as_str() {
        "GH" => gh::register(registry),
        other => Err(PackError::Unknown(other.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    Unknown(String),
    /// A pack's data file failed to parse. Packs ship their data inside the binary, so
    /// this means a bad edit and is caught by the test suite.
    Data {
        file: &'static str,
        reason: String,
    },
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(code) => write!(f, "there is no country pack for {code}"),
            Self::Data { file, reason } => write!(f, "the pack file {file} is invalid: {reason}"),
        }
    }
}

impl std::error::Error for PackError {}

pub(crate) fn pattern(source: &str) -> regex::Regex {
    match regex::Regex::new(source) {
        Ok(re) => re,
        // Built-in patterns are constants covered by tests.
        #[allow(clippy::panic)]
        Err(e) => panic!("invalid built-in pattern {source}: {e}"),
    }
}
