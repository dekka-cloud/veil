//! What each model label means as a Veil entity: its categories, sensitivity and
//! jurisdiction. Labels the table doesn't know keep their name and get the defaults.

use std::borrow::Cow;

use veil_core::{Category, EntityType, Finding, Jurisdiction, Sensitivity};

pub(crate) fn entity(label: &str) -> EntityType {
    EntityType(Cow::Owned(label.to_string()))
}

pub(crate) fn describe(finding: Finding, label: &str) -> Finding {
    use Category::*;
    let (categories, sensitivity): (&[Category], Sensitivity) = match label {
        "PERSON_NAME" | "PERSON_ALIAS" | "ACCOUNT_HOLDER_NAME" => {
            (&[PersonalIdentifier], Sensitivity::Personal)
        }
        "ADDRESS" => (
            &[LocationIdentifier, QuasiIdentifier],
            Sensitivity::Personal,
        ),
        "BANK_ACCOUNT_NUMBER" | "PAYMENT_CARD_PAN" => (
            &[FinancialInformation, PersonalIdentifier],
            Sensitivity::Sensitive,
        ),
        "PATIENT_ID" => (
            &[HealthInformation, PersonalIdentifier],
            Sensitivity::Sensitive,
        ),
        "GH_GHANA_CARD_PIN" | "GH_TAX_IDENTIFIER" => {
            (&[PersonalIdentifier], Sensitivity::Sensitive)
        }
        "GH_DIGITAL_ADDRESS" => (
            &[LocationIdentifier, PersonalIdentifier],
            Sensitivity::Personal,
        ),
        _ => (&[PersonalIdentifier], Sensitivity::Personal),
    };
    let mut f = categories
        .iter()
        .fold(finding, |f, c| f.category(*c))
        .sensitivity(sensitivity);
    if label.starts_with("GH_") {
        f = f.jurisdiction(Jurisdiction::GH);
    }
    f
}
