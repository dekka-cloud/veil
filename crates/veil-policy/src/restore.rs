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
    /// `[X_1]` never matches inside `[X_10]`. The text is read once, so a restored value
    /// that happens to look like a placeholder stays as it is.
    pub fn restore(&self, text: &str) -> String {
        let longest = self.entries.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(open) = rest.find('[') {
            let (before, tail) = rest.split_at(open);
            out.push_str(before);
            let (len, value) = tail
                .bytes()
                .take(longest)
                .position(|c| c == b']')
                .and_then(|close| tail.get(..=close))
                .and_then(|p| self.value(p).map(|v| (p.len(), v)))
                .unwrap_or((1, "["));
            out.push_str(value);
            rest = tail.get(len..).unwrap_or_default();
        }
        out.push_str(rest);
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
