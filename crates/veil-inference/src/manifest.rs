//! The manifest in a model directory: which files to load, their checksums, the label order of
//! the ONNX graph's output, the confidence threshold and the oldest Veil that can run it.

use serde::Deserialize;

use crate::ModelError;

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// The manifest format; this crate reads format 1.
    pub format: u32,
    pub id: String,
    pub version: String,
    pub model: FileRef,
    pub tokenizer: TokenizerRef,
    /// BIO tags in the order of the graph's output, starting with `O`.
    pub labels: Vec<String>,
    /// Spans whose mean label probability falls below this are dropped.
    pub threshold: f32,
    pub runtime: Runtime,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileRef {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenizerRef {
    pub file: String,
    pub sha256: String,
    pub max_length: usize,
    pub stride: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Runtime {
    /// The oldest Veil version that can run this model.
    pub veil: String,
}

fn version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((
        parts.next()??,
        parts.next().flatten().unwrap_or(0),
        parts.next().flatten().unwrap_or(0),
    ))
}

impl Manifest {
    pub(crate) fn check(&self, veil_version: &str) -> Result<(), ModelError> {
        if self.format != 1 {
            return Err(ModelError::Manifest(format!(
                "format {} isn't supported; this Veil reads format 1",
                self.format
            )));
        }
        if self.model.file.contains(['/', '\\']) || self.tokenizer.file.contains(['/', '\\']) {
            return Err(ModelError::Manifest(
                "model and tokenizer files must sit in the model directory".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.threshold) {
            return Err(ModelError::Manifest(format!(
                "threshold {} is outside 0 to 1",
                self.threshold
            )));
        }
        if self.tokenizer.max_length < 8 || self.tokenizer.stride >= self.tokenizer.max_length {
            return Err(ModelError::Manifest(
                "the tokenizer's stride must be smaller than its max_length, which must be at least 8".into(),
            ));
        }
        if self.labels.first().map(String::as_str) != Some("O") {
            return Err(ModelError::Labels("the first label must be O".into()));
        }
        for label in self.labels.iter().skip(1) {
            match label.split_once('-') {
                Some(("B" | "I", name)) if !name.is_empty() => {}
                _ => return Err(ModelError::Labels(format!("{label} isn't a B- or I- tag"))),
            }
        }
        let needs = version(&self.runtime.veil).ok_or_else(|| {
            ModelError::Manifest(format!(
                "runtime.veil {:?} isn't a version",
                self.runtime.veil
            ))
        })?;
        let have = version(veil_version)
            .ok_or_else(|| ModelError::Manifest(format!("{veil_version:?} isn't a version")))?;
        if needs > have {
            return Err(ModelError::Runtime {
                needs: self.runtime.veil.clone(),
                have: veil_version.to_string(),
            });
        }
        Ok(())
    }

    /// The entity labels, without B-/I- prefixes, in first-seen order.
    pub fn entity_labels(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in self.labels.iter().skip(1) {
            if let Some((_, name)) = l.split_once('-') {
                if !out.iter().any(|o| o == name) {
                    out.push(name.to_string());
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn manifest(extra: &str) -> Manifest {
        let src = format!(
            "format: 1\nid: m\nversion: 0.1.0\nmodel: {{file: model.onnx, sha256: aa}}\ntokenizer: {{file: tokenizer.json, sha256: bb, max_length: 256, stride: 32}}\nlabels: [O, B-PERSON_NAME, I-PERSON_NAME]\nthreshold: 0.5\nruntime: {{veil: {extra}}}\n"
        );
        serde_yaml_ng::from_str(&src).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn accepts_an_older_or_equal_runtime() {
        assert!(manifest("0.1.0").check("0.1.0").is_ok());
        assert!(manifest("0.0.9").check("0.1.0").is_ok());
    }

    #[test]
    fn refuses_a_newer_runtime() {
        assert!(matches!(
            manifest("0.2.0").check("0.1.0"),
            Err(ModelError::Runtime { .. })
        ));
    }

    #[test]
    fn refuses_labels_that_are_not_bio() {
        let mut m = manifest("0.1.0");
        m.labels.push("PERSON".into());
        assert!(matches!(m.check("0.1.0"), Err(ModelError::Labels(_))));
        m.labels = vec!["B-X".into()];
        assert!(matches!(m.check("0.1.0"), Err(ModelError::Labels(_))));
    }

    #[test]
    fn entity_labels_drop_prefixes() {
        assert_eq!(
            manifest("0.1.0").entity_labels(),
            vec!["PERSON_NAME".to_string()]
        );
    }
}
