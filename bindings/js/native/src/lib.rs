//! The native half of the `dekka-veil` npm package for Node.js. Scans run on libuv's thread
//! pool, so they never block the event loop, and answers come back in the shared JSON
//! contract with spans counted in UTF-16 code units, the way JavaScript indexes strings.

use std::sync::Arc;

use napi::bindgen_prelude::{AsyncTask, Env, Error, Result, Status, Task};
use napi_derive::napi;
use serde::Deserialize;
use veil::api::{self, DetectRequest, OffsetUnit, PolicySpec, ProtectRequest, RequestContext};
use veil::{Enforcement, Policy, Profile, Veil};

fn error(message: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, message.to_string())
}

/// Options for building an engine. Every field is optional.
#[napi(object)]
pub struct EngineOptions {
    /// Limits detection to one country's pack, such as `GH`.
    pub country: Option<String>,
    /// A built-in policy's name.
    pub policy: Option<String>,
    /// A policy written in YAML, which wins over `policy`.
    pub policy_yaml: Option<String>,
    /// A directory holding a model's `manifest.yaml`, `tokenizer.json` and `model.onnx`.
    pub model_dir: Option<String>,
    /// `rules`, `nano` or `hybrid`.
    pub profile: Option<String>,
    /// Threads one model inference may use.
    pub threads: Option<u32>,
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

#[derive(Debug)]
struct Inner {
    veil: Veil,
    policy: Policy,
    country: Option<String>,
}

impl Inner {
    fn protect(&self, call: &str) -> std::result::Result<String, String> {
        let call: Call = serde_json::from_str(call).map_err(|e| e.to_string())?;
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
            .map_err(|e| e.describe())?;
        let mut response = self
            .veil
            .protect_segments(&req, &self.policy, true)
            .map_err(|e| e.describe())?;
        response.reindex(&req.segments, OffsetUnit::Utf16);
        serde_json::to_string(&response).map_err(|e| e.to_string())
    }

    fn detect(&self, call: &str) -> std::result::Result<String, String> {
        let call: Call = serde_json::from_str(call).map_err(|e| e.to_string())?;
        let req = DetectRequest {
            segments: call.segments,
            country: self.country.clone(),
            context: call.context,
            profile: call.profile,
        };
        api::check_segments(&req.segments, self.veil.engine().config().max_input_bytes)
            .map_err(|e| e.describe())?;
        let mut response = self.veil.detect_segments(&req).map_err(|e| e.describe())?;
        response.reindex(&req.segments, OffsetUnit::Utf16);
        serde_json::to_string(&response).map_err(|e| e.to_string())
    }
}

fn profile(name: &str) -> Result<Profile> {
    match name {
        "rules" => Ok(Profile::Rules),
        "nano" => Ok(Profile::Nano),
        "hybrid" => Ok(Profile::Hybrid),
        other => Err(error(format!(
            "there is no profile called {other:?}; use rules, nano or hybrid"
        ))),
    }
}

/// A built Veil, shared by every call made on it.
#[napi]
pub struct Engine {
    inner: Arc<Inner>,
}

#[napi]
impl Engine {
    #[napi(constructor)]
    pub fn new(options: Option<EngineOptions>) -> Result<Self> {
        let options = options.unwrap_or(EngineOptions {
            country: None,
            policy: None,
            policy_yaml: None,
            model_dir: None,
            profile: None,
            threads: None,
        });
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
        let default_profile = if options.model_dir.is_some() {
            Profile::Hybrid
        } else {
            Profile::Rules
        };
        builder = builder.profile(match options.profile.as_deref() {
            Some(name) => profile(name)?,
            None => default_profile,
        });
        if let Some(dir) = options.model_dir {
            builder = builder
                .model_dir(dir)
                .model_threads(options.threads.unwrap_or(1) as usize);
        }
        let veil = builder.build().map_err(error)?;
        Ok(Self {
            inner: Arc::new(Inner {
                veil,
                policy,
                country: options.country,
            }),
        })
    }

    /// Protects the call's segments together and resolves to the response as JSON.
    #[napi(ts_return_type = "Promise<string>")]
    pub fn protect(&self, call: String) -> AsyncTask<Scan> {
        AsyncTask::new(Scan {
            inner: Arc::clone(&self.inner),
            call,
            protect: true,
        })
    }

    /// Detects personal information in the call's segments and resolves to the response as JSON.
    #[napi(ts_return_type = "Promise<string>")]
    pub fn detect(&self, call: String) -> AsyncTask<Scan> {
        AsyncTask::new(Scan {
            inner: Arc::clone(&self.inner),
            call,
            protect: false,
        })
    }

    /// The profile scans use unless they ask for another.
    #[napi(getter)]
    pub fn profile(&self) -> &'static str {
        api::profile_name(self.inner.veil.profile())
    }

    /// The policy's name and revision, such as `default-protection@2026-11-04`.
    #[napi(getter)]
    pub fn policy(&self) -> String {
        format!(
            "{}@{}",
            self.inner.policy.name,
            api::revision(&self.inner.policy)
        )
    }
}

/// One scan, run off the main thread.
pub struct Scan {
    inner: Arc<Inner>,
    call: String,
    protect: bool,
}

impl Task for Scan {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<String> {
        let answer = if self.protect {
            self.inner.protect(&self.call)
        } else {
            self.inner.detect(&self.call)
        };
        answer.map_err(error)
    }

    fn resolve(&mut self, _env: Env, output: String) -> Result<String> {
        Ok(output)
    }
}

/// Built-in policies, as JSON.
#[napi]
pub fn builtin_policies() -> Result<String> {
    serde_json::to_string(&api::builtin_policies()).map_err(error)
}

/// Every entity Veil can report, with its categories and sensitivity, as JSON.
#[napi]
pub fn entities() -> Result<String> {
    serde_json::to_string(&api::entities()).map_err(error)
}

/// Country packs and their versions, as JSON.
#[napi]
pub fn countries() -> Result<String> {
    serde_json::to_string(&api::countries()).map_err(error)
}

/// Checks a YAML policy and returns every problem with its path, as JSON.
#[napi]
pub fn validate_policy(yaml: String) -> Result<String> {
    serde_json::to_string(&api::validate_policy(&yaml)).map_err(error)
}

/// The version of the engine inside this package.
#[napi]
pub fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
