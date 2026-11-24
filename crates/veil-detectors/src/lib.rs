//! General detectors that apply in every country. Country-specific detectors live in
//! `veil-country-packs`.
//!
//! Every pattern uses the `regex` crate, which runs in linear time and cannot backtrack
//! catastrophically.

mod boundary;
pub mod card;
pub mod email;
pub mod ip;
pub mod secrets;
pub mod url;

pub use card::PaymentCardDetector;
pub use email::EmailDetector;
pub use ip::{Ipv4Detector, Ipv6Detector};
pub use secrets::SecretDetector;
pub use url::UrlParameterDetector;

use veil_core::Registry;

/// A registry with every general detector.
pub fn general() -> Registry {
    Registry::new()
        .with(EmailDetector::new())
        .with(Ipv4Detector::new())
        .with(Ipv6Detector::new())
        .with(PaymentCardDetector::new())
        .with(UrlParameterDetector::new())
        .with(SecretDetector::new())
}

/// Builds a regex from a literal pattern that is covered by tests.
pub(crate) fn pattern(source: &str) -> regex::Regex {
    match regex::Regex::new(source) {
        Ok(re) => re,
        // Patterns are constants checked by the test suite, so this can't fail at runtime.
        #[allow(clippy::panic)]
        Err(e) => panic!("invalid built-in pattern {source}: {e}"),
    }
}
