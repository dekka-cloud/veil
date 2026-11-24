//! Everything about a model except running its graph: the manifest, the tokenizer, the
//! overlapping windows a text is split into, and decoding the graph's logits back into
//! spans. Keeping this apart from ONNX Runtime lets a host that runs the graph some other
//! way, such as onnxruntime-web in a browser, produce exactly the spans the native runtime
//! does.

use std::collections::HashMap;
use std::sync::Mutex;

use tokenizers::{Encoding, Tokenizer, TruncationDirection, TruncationParams, TruncationStrategy};
use veil_core::{
    DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo, EntityType, Finding,
    Span, ValidationState,
};

use crate::decode::{self, Prediction};
use crate::{labels, verify, Manifest, ModelError};

/// A verified manifest and tokenizer, ready to plan and decode.
pub struct Pipeline {
    manifest: Manifest,
    tokenizer: Tokenizer,
    pad_id: i64,
    batch: usize,
    detector_id: &'static str,
    entity_types: Vec<EntityType>,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("id", &self.manifest.id)
            .field("version", &self.manifest.version)
            .finish_non_exhaustive()
    }
}

/// One batch of windows to run through the graph: `ids` and `mask` are row-major
/// `[rows, width]`, padded with the tokenizer's pad id and a zero mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub ids: Vec<i64>,
    pub mask: Vec<i64>,
    pub rows: usize,
    pub width: usize,
}

/// The windows a text was split into, grouped into batches. Run each batch's `ids` and
/// `mask` through the graph and hand [`Pipeline::decode`] one logits buffer per batch, of
/// shape `[rows, width, labels]`.
#[derive(Debug, Clone)]
pub struct Plan {
    batches: Vec<Batch>,
    windows: Vec<Vec<Encoding>>,
}

impl Plan {
    pub fn batches(&self) -> &[Batch] {
        &self.batches
    }

    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }
}

impl Pipeline {
    /// Builds a pipeline from a model's `manifest.yaml` and `tokenizer.json`, refusing a
    /// manifest that asks for a newer Veil or a tokenizer that doesn't match its checksum.
    /// `batch` is how many windows go to the graph at once.
    pub fn from_bytes(manifest: &[u8], tokenizer: &[u8], batch: usize) -> Result<Self, ModelError> {
        let manifest: Manifest =
            serde_yaml_ng::from_slice(manifest).map_err(|e| ModelError::Manifest(e.to_string()))?;
        manifest.check(env!("CARGO_PKG_VERSION"))?;
        verify(
            tokenizer,
            &manifest.tokenizer.sha256,
            &manifest.tokenizer.file,
        )?;

        let mut tokenizer =
            Tokenizer::from_bytes(tokenizer).map_err(|e| ModelError::Tokenizer(e.to_string()))?;
        let pad_id = tokenizer
            .get_padding()
            .map(|p| p.pad_id)
            .or_else(|| tokenizer.token_to_id("[PAD]"))
            .or_else(|| tokenizer.token_to_id("<pad>"))
            .unwrap_or(0);
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: manifest.tokenizer.max_length,
                stride: manifest.tokenizer.stride,
                strategy: TruncationStrategy::LongestFirst,
                direction: TruncationDirection::Right,
            }))
            .map_err(|e| ModelError::Tokenizer(e.to_string()))?;
        tokenizer.with_padding(None);

        // DetectorInfo wants a static id; a process loads a handful of models at most.
        let detector_id: &'static str =
            Box::leak(format!("{}-v{}", manifest.id, manifest.version).into_boxed_str());
        let mut entity_types: Vec<EntityType> = manifest
            .entity_labels()
            .iter()
            .map(|l| labels::entity(l))
            .collect();
        entity_types.sort();
        entity_types.dedup();
        Ok(Self {
            manifest,
            tokenizer,
            pad_id: i64::from(pad_id),
            batch: batch.max(1),
            detector_id,
            entity_types,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The id findings from this model carry, such as `veil-ner-nano-v0.3.0`.
    pub fn detector_id(&self) -> &'static str {
        self.detector_id
    }

    pub fn detector_info(&self) -> DetectorInfo {
        DetectorInfo {
            id: self.detector_id,
            description: "Veil's contextual model, for names, addresses and identifiers that only context reveals",
            entity_types: self.entity_types.clone(),
            jurisdiction: None,
            method: DetectionMethod::Model,
        }
    }

    /// Splits `text` into the model's overlapping windows and groups them into batches.
    /// Blank text has nothing to run.
    pub fn plan(&self, text: &str) -> Result<Plan, ModelError> {
        if text.trim().is_empty() {
            return Ok(Plan {
                batches: Vec::new(),
                windows: Vec::new(),
            });
        }
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| ModelError::Tokenizer(e.to_string()))?;
        let mut windows = vec![encoding.clone()];
        windows.extend(encoding.get_overflowing().iter().cloned());

        let mut batches = Vec::new();
        let mut grouped = Vec::new();
        for chunk in windows.chunks(self.batch) {
            let width = chunk.iter().map(|w| w.get_ids().len()).max().unwrap_or(0);
            if width == 0 {
                continue;
            }
            let mut ids = vec![self.pad_id; chunk.len() * width];
            let mut mask = vec![0i64; chunk.len() * width];
            for (row, w) in chunk.iter().enumerate() {
                for (col, (&id, &m)) in w.get_ids().iter().zip(w.get_attention_mask()).enumerate() {
                    if let (Some(i), Some(k)) = (
                        ids.get_mut(row * width + col),
                        mask.get_mut(row * width + col),
                    ) {
                        *i = i64::from(id);
                        *k = i64::from(m);
                    }
                }
            }
            batches.push(Batch {
                ids,
                mask,
                rows: chunk.len(),
                width,
            });
            grouped.push(chunk.to_vec());
        }
        Ok(Plan {
            batches,
            windows: grouped,
        })
    }

    /// Turns the graph's logits, one buffer per batch of `plan`, into spans at or above the
    /// manifest's threshold. Each token keeps the label from the window in which it sits
    /// furthest from an edge.
    pub fn decode(
        &self,
        text: &str,
        plan: &Plan,
        logits: &[&[f32]],
    ) -> Result<Vec<Prediction>, ModelError> {
        if logits.len() != plan.batches.len() {
            return Err(ModelError::Labels(format!(
                "expected logits for {} batches, got {}",
                plan.batches.len(),
                logits.len()
            )));
        }
        let n_labels = self.manifest.labels.len();
        let mut tokens = decode::Tokens::default();
        for ((batch, windows), logits) in plan.batches.iter().zip(&plan.windows).zip(logits) {
            if logits.len() != batch.rows * batch.width * n_labels {
                return Err(ModelError::Labels(format!(
                    "expected {} logits for a batch of {} windows of {} tokens and {} labels, got {}",
                    batch.rows * batch.width * n_labels,
                    batch.rows,
                    batch.width,
                    n_labels,
                    logits.len()
                )));
            }
            for (row, w) in windows.iter().enumerate() {
                let n = w.get_ids().len();
                for (t, &(start, end)) in w.get_offsets().iter().enumerate() {
                    let from = (row * batch.width + t) * n_labels;
                    let Some(row_logits) = logits.get(from..from + n_labels) else {
                        continue;
                    };
                    let (tag, prob) = decode::softmax_argmax(row_logits);
                    tokens.offer(
                        start,
                        end,
                        tag,
                        prob,
                        t.min(n.saturating_sub(1).saturating_sub(t)),
                    );
                }
            }
        }
        let spans = decode::decode(text, &tokens.in_order(), &self.manifest.labels);
        Ok(spans
            .into_iter()
            .filter(|p| p.score >= self.manifest.threshold)
            .collect())
    }

    /// The engine's findings for `predictions`, each marked unverified because a model's
    /// span is evidence rather than a checked format.
    pub fn findings(&self, predictions: Vec<Prediction>) -> Result<Vec<Finding>, DetectionError> {
        let mut out = Vec::with_capacity(predictions.len());
        for p in predictions {
            let span = Span::new(p.start, p.end).map_err(|e| DetectionError::new(e.to_string()))?;
            let finding = labels::describe(
                Finding::new(labels::entity(&p.label), span, self.detector_id),
                &p.label,
            )
            .confidence(p.score)
            .validation(ValidationState::Unverified);
            out.push(finding);
        }
        Ok(out)
    }
}

/// A model detector whose findings were computed before the scan, for hosts that run the
/// graph outside Rust. Give it each text's findings with [`PrecomputedDetector::provide`],
/// then run the engine; a text it has no findings for fails the model, so the engine falls
/// back to the rules and says so rather than reporting a model scan that didn't happen.
#[derive(Debug)]
pub struct PrecomputedDetector {
    info: DetectorInfo,
    findings: Mutex<HashMap<String, Vec<Finding>>>,
}

impl PrecomputedDetector {
    pub fn new(pipeline: &Pipeline) -> Self {
        Self {
            info: pipeline.detector_info(),
            findings: Mutex::new(HashMap::new()),
        }
    }

    /// Replaces the findings held for each text.
    pub fn provide(&self, findings: HashMap<String, Vec<Finding>>) {
        if let Ok(mut held) = self.findings.lock() {
            *held = findings;
        }
    }

    /// Drops every held text, so nothing outlives the call it was meant for.
    pub fn clear(&self) {
        if let Ok(mut held) = self.findings.lock() {
            held.clear();
        }
    }
}

impl Detector for PrecomputedDetector {
    fn info(&self) -> DetectorInfo {
        self.info.clone()
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let held = self
            .findings
            .lock()
            .map_err(|_| DetectionError::new("the model's findings are unavailable"))?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        held.get(text)
            .cloned()
            .ok_or_else(|| DetectionError::new("the model wasn't run on this text"))
    }
}
