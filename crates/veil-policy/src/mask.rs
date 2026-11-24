//! Entity-specific masking. Masks keep layout and separators so the result
//! still reads naturally, and reveal only what's needed to recognise the value.

use veil_core::EntityType;

const MASK: char = '*';

pub fn mask(entity: &EntityType, value: &str) -> String {
    match entity.as_str() {
        "GH_MOBILE_NUMBER" => keep_digits(value, 3, 4),
        // Keep the area code, such as 0302 for Accra, and the last three digits.
        "GH_LANDLINE_NUMBER" => keep_digits(value, 4, 3),
        "PAYMENT_CARD_PAN" => keep_digits(value, 0, 4),
        // The GHA prefix isn't personal, so it stays readable.
        "GH_GHANA_CARD_PIN" => keep_digits(value, 0, 2),
        "EMAIL_ADDRESS" => email(value),
        _ => keep_tail(value, 2),
    }
}

/// Masks every digit except the first `head` and the last `tail`, leaving separators and
/// other characters where they are.
fn keep_digits(value: &str, head: usize, tail: usize) -> String {
    let total = value.chars().filter(char::is_ascii_digit).count();
    let mut seen = 0;
    value
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                seen += 1;
                if seen <= head || seen > total.saturating_sub(tail) {
                    c
                } else {
                    MASK
                }
            } else {
                c
            }
        })
        .collect()
}

fn email(value: &str) -> String {
    match value.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => keep_tail(value, 2),
    }
}

/// Masks every alphanumeric character except the last `tail`.
fn keep_tail(value: &str, tail: usize) -> String {
    let total = value.chars().filter(|c| c.is_alphanumeric()).count();
    let mut seen = 0;
    value
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                seen += 1;
                if seen > total.saturating_sub(tail) {
                    c
                } else {
                    MASK
                }
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phones_keep_prefix_and_last_four() {
        assert_eq!(
            mask(&EntityType::GH_MOBILE_NUMBER, "024 123 4567"),
            "024 *** 4567"
        );
        assert_eq!(
            mask(&EntityType::GH_MOBILE_NUMBER, "+233 24 123 4567"),
            "+233 ** *** 4567"
        );
    }

    #[test]
    fn cards_keep_last_four() {
        assert_eq!(
            mask(&EntityType::PAYMENT_CARD_PAN, "4111 1111 1111 1111"),
            "**** **** **** 1111"
        );
    }

    #[test]
    fn emails_keep_first_letter_and_domain() {
        assert_eq!(
            mask(&EntityType::EMAIL_ADDRESS, "ama.mensah@example.com"),
            "a***@example.com"
        );
    }

    #[test]
    fn ghana_cards_keep_the_prefix_and_last_two_digits() {
        assert_eq!(
            mask(&EntityType::GH_GHANA_CARD_PIN, "GHA-123456789-0"),
            "GHA-********9-0"
        );
    }

    #[test]
    fn other_entities_keep_last_two() {
        assert_eq!(
            mask(&EntityType::GH_DIGITAL_ADDRESS, "AK-039-5028"),
            "**-***-**28"
        );
    }
}
