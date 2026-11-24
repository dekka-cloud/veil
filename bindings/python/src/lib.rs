//! The native half of the `dekka-veil` Python package. It builds a Veil and answers
//! requests in the shared JSON contract, with spans counted in code points so they index
//! Python strings directly. The Python half in `python/dekka_veil` turns those answers into
//! typed objects.

use std::path::PathBuf;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use veil::api::{self, DetectRequest, OffsetUnit, PolicySpec, ProtectRequest, RequestContext};
use veil::{Enforcement, Policy, Profile, Veil};

create_exception!(
    _veil,
    VeilError,
    PyException,
    "Raised when Veil can't build or can't answer a request."
);

fn error(message: impl std::fmt::Display) -> PyErr {
    VeilError::new_err(message.to_string())
}

fn profile(name: &str) -> PyResult<Profile> {
    match name {
        "rules" => Ok(Profile::Rules),
        "nano" => Ok(Profile::Nano),
        "hybrid" => Ok(Profile::Hybrid),
        other => Err(error(format!(
            "there is no profile called {other:?}; use rules, nano or hybrid"
        ))),
    }
}

fn enforcement(name: &str) -> PyResult<Enforcement> {
    match name {
        "closed" => Ok(Enforcement::Closed),
        "open" => Ok(Enforcement::Open),
        "rules_fallback" => Ok(Enforcement::RulesFallback),
        other => Err(error(format!(
            "there is no enforcement called {other:?}; use closed, open or rules_fallback"
        ))),
    }
}

fn context(json: Option<&str>) -> PyResult<RequestContext> {
    match json {
        None => Ok(RequestContext::default()),
        Some(json) => serde_json::from_str(json).map_err(error),
    }
}

/// A built Veil. Cheap to share across threads, and every scan releases the GIL.
#[pyclass(frozen, module = "dekka_veil._veil")]
struct Engine {
    veil: Veil,
    policy: Policy,
    country: Option<String>,
}

#[pymethods]
impl Engine {
    #[new]
    #[pyo3(signature = (*, country=None, policy=None, policy_yaml=None, model_dir=None, profile_name=None, threads=1))]
    fn new(
        country: Option<String>,
        policy: Option<String>,
        policy_yaml: Option<String>,
        model_dir: Option<PathBuf>,
        profile_name: Option<String>,
        threads: usize,
    ) -> PyResult<Self> {
        let spec = match (policy_yaml, policy) {
            (Some(yaml), _) => PolicySpec::Yaml { yaml },
            (None, Some(name)) => PolicySpec::Named { name },
            (None, None) => PolicySpec::default(),
        };
        let policy = api::compile_policy(&spec).map_err(|e| error(e.describe()))?;
        let mut builder = Veil::builder().policy(policy.clone());
        if let Some(code) = &country {
            builder = builder.country(code);
        }
        let default_profile = if model_dir.is_some() {
            Profile::Hybrid
        } else {
            Profile::Rules
        };
        builder = builder.profile(match profile_name.as_deref() {
            Some(name) => profile(name)?,
            None => default_profile,
        });
        if let Some(dir) = model_dir {
            builder = builder.model_dir(dir).model_threads(threads);
        }
        let veil = builder.build().map_err(error)?;
        Ok(Self {
            veil,
            policy,
            country,
        })
    }

    /// Protects `segments` together and returns the response as JSON.
    #[pyo3(signature = (segments, *, context_json=None, enforcement_name=None, restore=false, profile_name=None))]
    fn protect(
        &self,
        py: Python<'_>,
        segments: Vec<String>,
        context_json: Option<&str>,
        enforcement_name: Option<&str>,
        restore: bool,
        profile_name: Option<&str>,
    ) -> PyResult<String> {
        let req = ProtectRequest {
            segments,
            country: self.country.clone(),
            policy: PolicySpec::default(),
            context: context(context_json)?,
            enforcement: enforcement_name.map(enforcement).transpose()?,
            restore,
            profile: profile_name.map(profile).transpose()?,
        };
        let answer = py.detach(|| {
            api::check_segments(&req.segments, self.veil.engine().config().max_input_bytes)?;
            let mut response = self.veil.protect_segments(&req, &self.policy, true)?;
            response.reindex(&req.segments, OffsetUnit::CodePoint);
            Ok::<_, api::ApiError>(response)
        });
        let response = answer.map_err(|e| error(e.describe()))?;
        serde_json::to_string(&response).map_err(error)
    }

    /// Detects personal information in `segments` and returns the response as JSON.
    #[pyo3(signature = (segments, *, context_json=None, profile_name=None))]
    fn detect(
        &self,
        py: Python<'_>,
        segments: Vec<String>,
        context_json: Option<&str>,
        profile_name: Option<&str>,
    ) -> PyResult<String> {
        let req = DetectRequest {
            segments,
            country: self.country.clone(),
            context: context(context_json)?,
            profile: profile_name.map(profile).transpose()?,
        };
        let answer = py.detach(|| {
            api::check_segments(&req.segments, self.veil.engine().config().max_input_bytes)?;
            let mut response = self.veil.detect_segments(&req)?;
            response.reindex(&req.segments, OffsetUnit::CodePoint);
            Ok::<_, api::ApiError>(response)
        });
        let response = answer.map_err(|e| error(e.describe()))?;
        serde_json::to_string(&response).map_err(error)
    }

    /// The profile scans use unless they ask for another.
    #[getter]
    fn profile(&self) -> &'static str {
        api::profile_name(self.veil.profile())
    }

    /// The policy's name and revision, such as `default-protection@1`.
    #[getter]
    fn policy(&self) -> String {
        format!("{}@{}", self.policy.name, api::revision(&self.policy))
    }
}

/// Built-in policies, as JSON.
#[pyfunction]
fn builtin_policies() -> PyResult<String> {
    serde_json::to_string(&api::builtin_policies()).map_err(error)
}

/// Every entity Veil can report, with its categories and sensitivity, as JSON.
#[pyfunction]
fn entities() -> PyResult<String> {
    serde_json::to_string(&api::entities()).map_err(error)
}

/// Country packs and their versions, as JSON.
#[pyfunction]
fn countries() -> PyResult<String> {
    serde_json::to_string(&api::countries()).map_err(error)
}

/// Checks a YAML policy and returns every problem with its path, as JSON.
#[pyfunction]
fn validate_policy(yaml: &str) -> PyResult<String> {
    serde_json::to_string(&api::validate_policy(yaml)).map_err(error)
}

#[pymodule]
fn _veil(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Engine>()?;
    m.add("VeilError", m.py().get_type::<VeilError>())?;
    m.add_function(wrap_pyfunction!(builtin_policies, m)?)?;
    m.add_function(wrap_pyfunction!(entities, m)?)?;
    m.add_function(wrap_pyfunction!(countries, m)?)?;
    m.add_function(wrap_pyfunction!(validate_policy, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
