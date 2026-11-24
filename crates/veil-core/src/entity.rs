//! The entity model. An entity type is a stable code such as
//! `GH_MOBILE_NUMBER`; categories, sensitivity and jurisdiction are separate dimensions.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A stable entity code. Country packs define their own, so this is a string rather than
/// a closed enum; the codes Veil ships are constants on this type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityType(pub Cow<'static, str>);

impl EntityType {
    pub const fn new(code: &'static str) -> Self {
        Self(Cow::Borrowed(code))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const EMAIL_ADDRESS: Self = Self::new("EMAIL_ADDRESS");
    pub const IP_ADDRESS: Self = Self::new("IP_ADDRESS");
    pub const PAYMENT_CARD_PAN: Self = Self::new("PAYMENT_CARD_PAN");
    pub const GH_MOBILE_NUMBER: Self = Self::new("GH_MOBILE_NUMBER");
    pub const GH_LANDLINE_NUMBER: Self = Self::new("GH_LANDLINE_NUMBER");
    pub const GH_GHANA_CARD_PIN: Self = Self::new("GH_GHANA_CARD_PIN");
    pub const GH_DIGITAL_ADDRESS: Self = Self::new("GH_DIGITAL_ADDRESS");
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    PersonalIdentifier,
    QuasiIdentifier,
    SensitiveContent,
    FinancialInformation,
    HealthInformation,
    Credential,
    OrganisationalIdentifier,
    LocationIdentifier,
}

/// Which family a finding belongs to. Personal information, secrets such as
/// API keys, and sensitive content such as a diagnosis are protected differently, so
/// policies can tell them apart.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Family {
    #[default]
    Pii,
    Secret,
    SensitiveContent,
}

/// Veil's own policy labels, not statutory categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Sensitivity {
    Public,
    Internal,
    Personal,
    Sensitive,
    HighlySensitive,
}

/// An ISO 3166-1 alpha-2 country code, or none for identifiers that aren't national.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Jurisdiction(pub Cow<'static, str>);

impl Jurisdiction {
    pub const GH: Self = Self(Cow::Borrowed("GH"));

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
