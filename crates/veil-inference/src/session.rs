//! The model run in-process through ONNX Runtime.

use std::path::Path;
use std::sync::Mutex;

use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;
use veil_core::cancel::cancelled;
use veil_core::{DetectionContext, DetectionError, Detector, DetectorInfo, Finding};

use crate::decode::Prediction;
use crate::pipeline::Pipeline;
use crate::{read, verify, Manifest, ModelError, Options};

/// A loaded, verified model.
pub struct Model {
    pipeline: Pipeline,
    // ort 2.0's Session::run takes &mut self, so concurrent requests take turns.
    session: Mutex<Session>,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("pipeline", &self.pipeline)
            .finish_non_exhaustive()
    }
}

fn onnx(e: ort::Error) -> ModelError {
    ModelError::Onnx(e.to_string())
}

impl Model {
    /// Loads and verifies the model in `dir`.
    pub fn load(dir: impl AsRef<Path>, options: Options) -> Result<Self, ModelError> {
        let dir = dir.as_ref();
        let manifest_bytes = read(&dir.join("manifest.yaml"))?;
        let manifest: Manifest = serde_yaml_ng::from_slice(&manifest_bytes)
            .map_err(|e| ModelError::Manifest(e.to_string()))?;
        // Checked before the files it names are read, so they're read from `dir` only.
        manifest.check(env!("CARGO_PKG_VERSION"))?;
        let model_bytes = read(&dir.join(&manifest.model.file))?;
        verify(&model_bytes, &manifest.model.sha256, &manifest.model.file)?;
        let tokenizer_bytes = read(&dir.join(&manifest.tokenizer.file))?;
        let pipeline = Pipeline::from_bytes(&manifest_bytes, &tokenizer_bytes, options.batch)?;

        let session = Session::builder()
            .map_err(onnx)?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(onnx)?
            .with_intra_threads(options.threads.max(1))
            .map_err(onnx)?
            .with_inter_threads(1)
            .map_err(onnx)?
            .commit_from_memory(&model_bytes)
            .map_err(onnx)?;
        let inputs: Vec<&str> = session.inputs.iter().map(|i| i.name.as_str()).collect();
        if !inputs.contains(&"input_ids") || !inputs.contains(&"attention_mask") {
            return Err(ModelError::Onnx(format!(
                "expected inputs input_ids and attention_mask, found {}",
                inputs.join(", ")
            )));
        }
        let logits = session
            .outputs
            .iter()
            .find(|o| o.name == "logits")
            .ok_or_else(|| ModelError::Onnx("the graph has no logits output".into()))?;
        if let ort::value::ValueType::Tensor { shape, .. } = &logits.output_type {
            if let Some(&n) = shape.last() {
                let labels = pipeline.manifest().labels.len();
                if n > 0 && usize::try_from(n).ok() != Some(labels) {
                    return Err(ModelError::Labels(format!(
                        "the graph has {n} outputs per token and the manifest lists {labels} labels"
                    )));
                }
            }
        }
        Ok(Self {
            pipeline,
            session: Mutex::new(session),
        })
    }

    pub fn manifest(&self) -> &Manifest {
        self.pipeline.manifest()
    }

    pub fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    /// Spans the model finds in `text`, at or above the manifest's threshold, as byte offsets.
    /// A long text is many batches, so a scan cancelled through [`veil_core::Cancel`] stops
    /// before the next one.
    pub fn predict(&self, text: &str) -> Result<Vec<Prediction>, ModelError> {
        let plan = self.pipeline.plan(text)?;
        if plan.is_empty() {
            return Ok(Vec::new());
        }
        let n_labels = self.pipeline.manifest().labels.len();
        let mut all = Vec::with_capacity(plan.batches().len());
        for batch in plan.batches() {
            let shape = [batch.rows, batch.width];
            let ids = Tensor::from_array((shape, batch.ids.clone())).map_err(onnx)?;
            let mask = Tensor::from_array((shape, batch.mask.clone())).map_err(onnx)?;
            let mut session = self
                .session
                .lock()
                .map_err(|_| ModelError::Onnx("a previous inference panicked".into()))?;
            // Looked at with the session in hand, because a scan that shares the model
            // spends its time waiting here and may have been cancelled meanwhile.
            if cancelled() {
                return Err(ModelError::Cancelled);
            }
            let outputs = session
                .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
                .map_err(onnx)?;
            let logits = outputs
                .get("logits")
                .ok_or_else(|| ModelError::Onnx("the model returned no logits".into()))?;
            let (out_shape, logits) = logits.try_extract_tensor::<f32>().map_err(onnx)?;
            let dims: Vec<i64> = out_shape.iter().copied().collect();
            let want =
                [batch.rows, batch.width, n_labels].map(|d| i64::try_from(d).unwrap_or(i64::MAX));
            if dims != want {
                return Err(ModelError::Labels(format!(
                    "expected logits of shape {want:?}, got {dims:?}"
                )));
            }
            all.push(logits.to_vec());
        }
        let views: Vec<&[f32]> = all.iter().map(Vec::as_slice).collect();
        self.pipeline.decode(text, &plan, &views)
    }
}

/// The model as a detector, so the engine can run it beside the rules.
#[derive(Debug)]
pub struct ModelDetector {
    model: Model,
}

impl ModelDetector {
    pub fn new(model: Model) -> Self {
        Self { model }
    }

    pub fn load(dir: impl AsRef<Path>, options: Options) -> Result<Self, ModelError> {
        Model::load(dir, options).map(Self::new)
    }

    pub fn model(&self) -> &Model {
        &self.model
    }
}

impl Detector for ModelDetector {
    fn info(&self) -> DetectorInfo {
        self.model.pipeline.detector_info()
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let predictions = self
            .model
            .predict(text)
            .map_err(|e| DetectionError::new(e.to_string()))?;
        self.model.pipeline.findings(predictions)
    }
}
