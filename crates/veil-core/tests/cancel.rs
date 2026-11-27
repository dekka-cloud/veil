//! A cancelled scan stops before its next detector and never passes for a finished one.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use veil_core::{
    Cancel, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo, Engine,
    Finding, Profile, Registry, VeilError,
};

/// Counts its runs, and cancels the scan from inside when it holds a flag, as a host would
/// from another thread while the detector worked.
#[derive(Debug)]
struct Step {
    id: &'static str,
    method: DetectionMethod,
    cancel: Option<Cancel>,
    runs: Arc<AtomicUsize>,
}

impl Detector for Step {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: self.id,
            description: "test",
            entity_types: Vec::new(),
            jurisdiction: None,
            method: self.method,
        }
    }

    fn detect(&self, _: &str, _: &DetectionContext) -> Result<Vec<Finding>, DetectionError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        Ok(Vec::new())
    }
}

fn step(id: &'static str, cancel: Option<&Cancel>, runs: &Arc<AtomicUsize>) -> Step {
    Step {
        id,
        method: DetectionMethod::Pattern,
        cancel: cancel.cloned(),
        runs: runs.clone(),
    }
}

#[test]
fn a_cancelled_scan_stops_before_the_next_detector() {
    let (cancel, runs) = (Cancel::new(), Arc::new(AtomicUsize::new(0)));
    let engine = Engine::new(
        Registry::new()
            .with(step("first", Some(&cancel), &runs))
            .with(step("second", None, &runs)),
    );
    let context = DetectionContext::default();
    let result = cancel.scope(|| engine.detect("some text", &context));
    assert_eq!(result, Err(VeilError::Cancelled));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[test]
fn a_flag_only_reaches_scans_run_under_it() {
    let (cancel, runs) = (Cancel::new(), Arc::new(AtomicUsize::new(0)));
    let engine = Engine::new(Registry::new().with(step("only", None, &runs)));
    let context = DetectionContext::default();
    cancel.cancel();
    assert!(engine.detect("some text", &context).is_ok());
    // An inner scope ends without disturbing the flag around it.
    let outer = Cancel::new();
    let result = outer.scope(|| {
        assert!(cancel
            .scope(|| engine.detect("some text", &context))
            .is_err());
        engine.detect("some text", &context)
    });
    assert!(result.is_ok());
    assert!(engine.detect("some text", &context).is_ok());
}

#[test]
fn a_scan_cancelled_in_the_model_does_not_fall_back_to_the_rules() {
    let (cancel, runs) = (Cancel::new(), Arc::new(AtomicUsize::new(0)));
    let model = Step {
        method: DetectionMethod::Model,
        ..step("model", Some(&cancel), &runs)
    };
    let engine =
        Engine::new(Registry::new().with(step("rule", None, &runs))).with_model(Box::new(model));
    let context = DetectionContext::default();
    for profile in [Profile::Nano, Profile::Hybrid] {
        let fresh = Cancel::new();
        assert!(fresh
            .scope(|| engine.detect_with("some text", &context, profile))
            .is_ok());
    }
    runs.store(0, Ordering::SeqCst);
    let result = cancel.scope(|| engine.detect_with("some text", &context, Profile::Hybrid));
    assert_eq!(result, Err(VeilError::Cancelled));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}
