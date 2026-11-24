//! Veil compiled to WebAssembly for browsers and other JavaScript runtimes without native
//! addons. The rules run here in full. The contextual model's graph can't, because ONNX
//! Runtime has no WebAssembly build for Rust, so it runs in onnxruntime-web instead: this
//! crate tokenises each text into the model's windows, the JavaScript layer runs them, and
//! the logits come back here to be decoded exactly as the native runtime decodes them.
//! Answers use the shared JSON contract with spans counted in UTF-16 code units.

use std::collections::HashMap;
use std::sync::Arc;

use js_sys::{Array, BigInt64Array, Float32Array};
use serde::Deserialize;
use veil::api::{self, DetectRequest, OffsetUnit, PolicySpec, ProtectRequest, RequestContext};
use veil::{
    DetectionContext, DetectionError, Detector, DetectorInfo, Enforcement, Finding, Policy,
    Profile, Veil,
};
use veil_inference::{Pipeline, Plan, PrecomputedDetector};
use wasm_bindgen::prelude::*;

fn error(message: impl std::fmt::Display) -> JsError {
    JsError::new(&message.to_string())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    policy: Option<String>,
    #[serde(default)]
    policy_yaml: Option<String>,
    #[serde(default)]
    profile: Option<Profile>,
}

/// One call's settings, as the JavaScript layer sends them.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    segments: Vec<String>,
    #[serde(default)]
    context: RequestContext,
    #[serde(default)]
    enforcement: Option<Enforcement>,
    #[serde(default)]
    restore: bool,
    #[serde(default)]
    profile: Option<Profile>,
}

/// The engine and this wrapper both hold the detector, so the wrapper can hand it each
/// text's findings before a scan.
#[derive(Debug)]
struct Shared(Arc<PrecomputedDetector>);

impl Detector for Shared {
    fn info(&self) -> DetectorInfo {
        self.0.info()
    }

    fn detect(
        &self,
        text: &str,
        context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        self.0.detect(text, context)
    }
}

/// A built Veil. With a model, call [`Engine::plan`] on each text, run its batches through
/// onnxruntime-web, hand the logits to [`Engine::provide`], then protect or detect.
#[wasm_bindgen]
pub struct Engine {
    veil: Veil,
    policy: Policy,
    country: Option<String>,
    model: Option<(Pipeline, Arc<PrecomputedDetector>)>,
    pending: HashMap<String, Vec<Finding>>,
}

#[wasm_bindgen]
impl Engine {
    /// Builds an engine from JSON options (`country`, `policy`, `policy_yaml`, `profile`),
    /// with a model when its `manifest.yaml` and `tokenizer.json` are given.
    #[wasm_bindgen(constructor)]
    pub fn new(
        options: &str,
        manifest: Option<Vec<u8>>,
        tokenizer: Option<Vec<u8>>,
    ) -> Result<Engine, JsError> {
        let options: Options = serde_json::from_str(options).map_err(error)?;
        let spec = match (options.policy_yaml, options.policy) {
            (Some(yaml), _) => PolicySpec::Yaml { yaml },
            (None, Some(name)) => PolicySpec::Named { name },
            (None, None) => PolicySpec::default(),
        };
        let policy = api::compile_policy(&spec).map_err(|e| error(e.describe()))?;
        let mut builder = Veil::builder().policy(policy.clone());
        if let Some(code) = &options.country {
            builder = builder.country(code);
        }
        let model = match (manifest, tokenizer) {
            (Some(manifest), Some(tokenizer)) => {
                let pipeline = Pipeline::from_bytes(&manifest, &tokenizer, 8).map_err(error)?;
                let detector = Arc::new(PrecomputedDetector::new(&pipeline));
                builder = builder.model(Shared(Arc::clone(&detector)));
                Some((pipeline, detector))
            }
            (None, None) => None,
            _ => return Err(error("a model needs both its manifest and its tokenizer")),
        };
        let default_profile = if model.is_some() {
            Profile::Hybrid
        } else {
            Profile::Rules
        };
        builder = builder.profile(options.profile.unwrap_or(default_profile));
        let veil = builder.build().map_err(error)?;
        Ok(Engine {
            veil,
            policy,
            country: options.country,
            model,
            pending: HashMap::new(),
        })
    }

    /// Splits `text` into the model's windows, ready to run.
    pub fn plan(&self, text: &str) -> Result<TextPlan, JsError> {
        let (pipeline, _) = self
            .model
            .as_ref()
            .ok_or_else(|| error("this engine has no model"))?;
        let plan = pipeline.plan(text).map_err(error)?;
        Ok(TextPlan {
            text: text.to_string(),
            plan,
        })
    }

    /// Decodes the graph's logits for a planned text, one `Float32Array` per batch, and keeps
    /// the findings for the next scan of that text.
    pub fn provide(&mut self, planned: &TextPlan, logits: Array) -> Result<(), JsError> {
        let (pipeline, _) = self
            .model
            .as_ref()
            .ok_or_else(|| error("this engine has no model"))?;
        let buffers: Vec<Vec<f32>> = logits
            .iter()
            .map(|l| Float32Array::from(l).to_vec())
            .collect();
        let views: Vec<&[f32]> = buffers.iter().map(Vec::as_slice).collect();
        let predictions = pipeline
            .decode(&planned.text, &planned.plan, &views)
            .map_err(error)?;
        let findings = pipeline.findings(predictions).map_err(error)?;
        self.pending.insert(planned.text.clone(), findings);
        Ok(())
    }

    /// Protects the call's segments together and returns the response as JSON.
    pub fn protect(&mut self, call: &str) -> Result<String, JsError> {
        let call: Call = serde_json::from_str(call).map_err(error)?;
        let req = ProtectRequest {
            segments: call.segments,
            country: self.country.clone(),
            policy: PolicySpec::default(),
            context: call.context,
            enforcement: call.enforcement,
            restore: call.restore,
            profile: call.profile,
        };
        api::check_segments(&req.segments, self.veil.engine().config().max_input_bytes)
            .map_err(|e| error(e.describe()))?;
        self.hand_over();
        let answer = self.veil.protect_segments(&req, &self.policy, true);
        self.forget();
        let mut response = answer.map_err(|e| error(e.describe()))?;
        response.reindex(&req.segments, OffsetUnit::Utf16);
        serde_json::to_string(&response).map_err(error)
    }

    /// Detects personal information in the call's segments and returns the response as JSON.
    pub fn detect(&mut self, call: &str) -> Result<String, JsError> {
        let call: Call = serde_json::from_str(call).map_err(error)?;
        let req = DetectRequest {
            segments: call.segments,
            country: self.country.clone(),
            context: call.context,
            profile: call.profile,
        };
        api::check_segments(&req.segments, self.veil.engine().config().max_input_bytes)
            .map_err(|e| error(e.describe()))?;
        self.hand_over();
        let answer = self.veil.detect_segments(&req);
        self.forget();
        let mut response = answer.map_err(|e| error(e.describe()))?;
        response.reindex(&req.segments, OffsetUnit::Utf16);
        serde_json::to_string(&response).map_err(error)
    }

    /// The profile scans use unless they ask for another.
    #[wasm_bindgen(getter)]
    pub fn profile(&self) -> String {
        api::profile_name(self.veil.profile()).to_string()
    }

    /// The policy's name and revision, such as `default-protection@2026-11-04`.
    #[wasm_bindgen(getter)]
    pub fn policy(&self) -> String {
        format!("{}@{}", self.policy.name, api::revision(&self.policy))
    }

    /// The SHA-256 the model's graph must have, from its manifest.
    #[wasm_bindgen(getter, js_name = modelSha256)]
    pub fn model_sha256(&self) -> Option<String> {
        self.model
            .as_ref()
            .map(|(p, _)| p.manifest().model.sha256.clone())
    }

    /// The model's id and version, such as `veil-ner-nano-v0.3.0`.
    #[wasm_bindgen(getter, js_name = modelId)]
    pub fn model_id(&self) -> Option<String> {
        self.model
            .as_ref()
            .map(|(p, _)| p.detector_id().to_string())
    }

    fn hand_over(&mut self) {
        if let Some((_, detector)) = &self.model {
            detector.provide(std::mem::take(&mut self.pending));
        }
    }

    fn forget(&mut self) {
        if let Some((_, detector)) = &self.model {
            detector.clear();
        }
        self.pending.clear();
    }
}

/// One text split into the model's windows, grouped into batches to run.
#[wasm_bindgen]
pub struct TextPlan {
    text: String,
    plan: Plan,
}

#[wasm_bindgen]
impl TextPlan {
    /// How many batches to run.
    #[wasm_bindgen(getter)]
    pub fn batches(&self) -> usize {
        self.plan.batches().len()
    }

    /// The `input_ids` of batch `i`, row-major `[rows, width]`.
    pub fn ids(&self, i: usize) -> Result<BigInt64Array, JsError> {
        let batch = self
            .plan
            .batches()
            .get(i)
            .ok_or_else(|| error("there is no such batch"))?;
        Ok(BigInt64Array::from(batch.ids.as_slice()))
    }

    /// The `attention_mask` of batch `i`, row-major `[rows, width]`.
    pub fn mask(&self, i: usize) -> Result<BigInt64Array, JsError> {
        let batch = self
            .plan
            .batches()
            .get(i)
            .ok_or_else(|| error("there is no such batch"))?;
        Ok(BigInt64Array::from(batch.mask.as_slice()))
    }

    /// The shape of batch `i`, `[rows, width]`.
    pub fn shape(&self, i: usize) -> Result<Vec<u32>, JsError> {
        let batch = self
            .plan
            .batches()
            .get(i)
            .ok_or_else(|| error("there is no such batch"))?;
        let dim = |n: usize| u32::try_from(n).map_err(|_| error("a batch is too large"));
        Ok(vec![dim(batch.rows)?, dim(batch.width)?])
    }
}

/// Built-in policies, as JSON.
#[wasm_bindgen(js_name = builtinPolicies)]
pub fn builtin_policies() -> Result<String, JsError> {
    serde_json::to_string(&api::builtin_policies()).map_err(error)
}

/// Every entity Veil can report, with its categories and sensitivity, as JSON.
#[wasm_bindgen]
pub fn entities() -> Result<String, JsError> {
    serde_json::to_string(&api::entities()).map_err(error)
}

/// Country packs and their versions, as JSON.
#[wasm_bindgen]
pub fn countries() -> Result<String, JsError> {
    serde_json::to_string(&api::countries()).map_err(error)
}

/// Checks a YAML policy and returns every problem with its path, as JSON.
#[wasm_bindgen(js_name = validatePolicy)]
pub fn validate_policy(yaml: &str) -> Result<String, JsError> {
    serde_json::to_string(&api::validate_policy(yaml)).map_err(error)
}

/// The version of the engine inside this package.
#[wasm_bindgen(js_name = engineVersion)]
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
