//! Runs Veil's contextual model.
//!
//! A model directory holds three files: `model.onnx`, `tokenizer.json` and `manifest.yaml`.
//! Loading refuses a directory whose files don't match the SHA-256 in the manifest, whose
//! labels don't match the ONNX graph, or whose manifest asks for a newer Veil. Text is
//! tokenised with the Hugging Face `tokenizers` crate, the graph runs through ONNX Runtime,
//! and BIO tags are decoded into byte spans exactly as the reference decoder published with
//! each model does, so every runtime reports the same spans for the same model.
//!
//! Text longer than the model's window is split into overlapping windows, and each token keeps
//! the prediction from the window in which it sits furthest from an edge. A span's confidence
//! is the mean probability of its tokens' labels, and spans below the manifest's threshold
//! are dropped.
//!
//! [`Pipeline`] does everything except run the graph, so it builds anywhere, WebAssembly
//! included. With the `onnxruntime` feature (on by default), `Model` runs the graph
//! in-process and `ModelDetector` hands its findings to the engine. A host that runs the
//! graph elsewhere, such as onnxruntime-web in a browser, plans with [`Pipeline::plan`],
//! decodes with [`Pipeline::decode`] and gives the engine a [`PrecomputedDetector`].

mod decode;
mod labels;
mod manifest;
mod pipeline;
#[cfg(feature = "onnxruntime")]
mod session;

use sha2::{Digest, Sha256};
use thiserror::Error;

pub use decode::Prediction;
pub use manifest::Manifest;
pub use pipeline::{Batch, Pipeline, Plan, PrecomputedDetector};
#[cfg(feature = "onnxruntime")]
pub use session::{Model, ModelDetector};

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("couldn't read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("the model manifest is invalid: {0}")]
    Manifest(String),
    #[error("{file} doesn't match the SHA-256 in the manifest")]
    Checksum { file: String },
    #[error("the model's labels don't match: {0}")]
    Labels(String),
    #[error("the model needs Veil {needs} or later, and this is {have}")]
    Runtime { needs: String, have: String },
    #[error("ONNX Runtime: {0}")]
    Onnx(String),
    #[error("tokenizer: {0}")]
    Tokenizer(String),
}

/// Inference settings that belong to the host rather than the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Threads ONNX Runtime may use within one inference. One keeps latency predictable
    /// when many requests run at once.
    pub threads: usize,
    /// Windows sent to the graph in one batch.
    pub batch: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: 1,
            batch: 8,
        }
    }
}

#[cfg(feature = "onnxruntime")]
fn read(path: &std::path::Path) -> Result<Vec<u8>, ModelError> {
    std::fs::read(path).map_err(|source| ModelError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Checks `bytes` against a hex SHA-256 from the manifest.
pub fn verify(bytes: &[u8], want: &str, file: &str) -> Result<(), ModelError> {
    use std::fmt::Write as _;
    let got = Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
    if got.eq_ignore_ascii_case(want.trim()) {
        Ok(())
    } else {
        Err(ModelError::Checksum {
            file: file.to_string(),
        })
    }
}
