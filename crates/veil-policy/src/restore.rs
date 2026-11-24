use std::fmt;

/// Placeholders made by tokenisation and the values they stand for, so a caller such as an
/// AI gateway can put the real values back into a model's reply. It holds personal
/// information: it can't be serialised, its `Debug` output hides the values, and it should
/// be dropped when the request ends.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct RestoreMap {
    entries: Vec<(String, String)>,
}

impl RestoreMap {
    pub(crate) fn insert(&mut self, placeholder: &str, value: &str) {
        if !self.entries.iter().any(|(p, _)| p == placeholder) {
            self.entries
                .push((placeholder.to_string(), value.to_string()));
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The placeholders, without their values.
    pub fn placeholders(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(p, _)| p.as_str())
    }

    /// The value a placeholder stands for.
    pub fn value(&self, placeholder: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(p, _)| p == placeholder)
            .map(|(_, v)| v.as_str())
    }

    /// Replaces every placeholder in `text` with its value. Placeholders end in `]`, so
    /// `[X_1]` never matches inside `[X_10]`.
    pub fn restore(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (placeholder, value) in &self.entries {
            if out.contains(placeholder.as_str()) {
                out = out.replace(placeholder.as_str(), value);
            }
        }
        out
    }
}

impl fmt::Debug for RestoreMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestoreMap")
            .field(
                "placeholders",
                &self.entries.iter().map(|(p, _)| p).collect::<Vec<_>>(),
            )
            .finish()
    }
}
