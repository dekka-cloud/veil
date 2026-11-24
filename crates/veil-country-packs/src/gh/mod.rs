//! The Ghana pack.

mod card;
mod digital_address;
mod patterns;
mod phone;
mod spoken;

pub use card::GhanaCardDetector;
pub use digital_address::DigitalAddressDetector;
pub use patterns::PatternDetector;
pub use phone::PhoneDetector;
pub use spoken::SpokenPhoneDetector;

use std::collections::BTreeMap;

use veil_core::{
    DetectionContext, DetectionError, Detector, DetectorInfo, EvidenceLevel, Finding, Jurisdiction,
    Registry,
};

use crate::PackError;

pub const JURISDICTION: Jurisdiction = Jurisdiction::GH;
pub const MANIFEST: &str = include_str!("../../../../country-packs/gh/manifest.toml");
pub const NUMBERING: &str = include_str!("../../../../country-packs/gh/numbering.toml");
pub const GHANA_CARD: &str = include_str!("../../../../country-packs/gh/ghana-card.toml");
pub const DIGITAL_ADDRESS: &str = include_str!("../../../../country-packs/gh/digital-address.toml");
pub const PATTERNS: &str = include_str!("../../../../country-packs/gh/patterns.toml");
pub const SPOKEN_DIGITS: &str = include_str!("../../../../country-packs/gh/spoken-digits.toml");

pub fn register(registry: &mut Registry) -> Result<(), PackError> {
    let evidence = manifest()?.evidence;
    let mut add = |d: Box<dyn Detector>| {
        registry.register(Box::new(Evidenced {
            inner: d,
            evidence: evidence.clone(),
        }))
    };
    add(Box::new(PhoneDetector::new()?));
    add(Box::new(SpokenPhoneDetector::new()?));
    add(Box::new(GhanaCardDetector::new()?));
    add(Box::new(DigitalAddressDetector::new()?));
    for d in patterns::detectors()? {
        add(Box::new(d));
    }
    Ok(())
}

/// A pack detector whose findings carry their entity's evidence level from the manifest.
#[derive(Debug)]
struct Evidenced {
    inner: Box<dyn Detector>,
    evidence: BTreeMap<String, EvidenceLevel>,
}

impl Detector for Evidenced {
    fn info(&self) -> DetectorInfo {
        self.inner.info()
    }

    fn detect(
        &self,
        text: &str,
        context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let mut found = self.inner.detect(text, context)?;
        for f in &mut found {
            f.evidence = self.evidence.get(f.entity_type.as_str()).copied();
        }
        Ok(found)
    }
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    file: &'static str,
    source: &str,
) -> Result<T, PackError> {
    toml::from_str(source).map_err(|e| PackError::Data {
        file,
        reason: e.to_string(),
    })
}

#[derive(Debug, serde::Deserialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub taxonomy_version: String,
    pub entities: Vec<String>,
    pub languages: Vec<String>,
    /// Each detected entity's evidence level, from the identifier registry.
    #[serde(default)]
    pub evidence: BTreeMap<String, EvidenceLevel>,
}

pub fn manifest() -> Result<Manifest, PackError> {
    parse("gh/manifest.toml", MANIFEST)
}
