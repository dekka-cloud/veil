//! Runs every fixture file through the full rules engine: the general detectors plus the
//! Ghana pack. Each expected finding must be reported with exactly that value and those
//! labels, and nothing else may be reported, so hard negatives catch false positives.

// Tests and examples may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::{Path, PathBuf};

use serde::Deserialize;
use veil_core::{DetectionContext, Engine};

#[derive(Debug, Deserialize)]
struct Case {
    text: String,
    expect: Vec<Expected>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    entity: String,
    value: String,
    /// Labels that must be present. An explicit empty list means no labels at all.
    labels: Option<Vec<String>>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn engine() -> Engine {
    let mut registry = veil_detectors::general();
    veil_country_packs::register("gh", &mut registry).expect("the Ghana pack loads");
    Engine::new(registry)
}

fn files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in ["tests/fixtures", "country-packs/gh/fixtures"] {
        let mut files: Vec<PathBuf> = std::fs::read_dir(root().join(dir))
            .expect("fixtures dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        files.sort();
        out.extend(files);
    }
    out
}

#[test]
fn every_fixture_passes() {
    let engine = engine();
    let ctx = DetectionContext::default();
    let mut failures = Vec::new();
    let mut cases = 0;
    for file in files() {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        for (i, line) in std::fs::read_to_string(&file)
            .expect("read fixture")
            .lines()
            .enumerate()
        {
            if line.trim().is_empty() {
                continue;
            }
            cases += 1;
            let case: Case = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{name}:{} is not valid: {e}", i + 1));
            let found = engine
                .detect(&case.text, &ctx)
                .expect("detection runs")
                .findings;
            let got: Vec<(String, String, Vec<String>)> = found
                .iter()
                .map(|f| {
                    (
                        f.entity_type.to_string(),
                        f.span.slice(&case.text).expect("valid span").to_string(),
                        f.context_labels.clone(),
                    )
                })
                .collect();
            let mut problems = Vec::new();
            for e in &case.expect {
                match got
                    .iter()
                    .find(|(entity, value, _)| *entity == e.entity && *value == e.value)
                {
                    None => problems.push(format!("missed {} {:?}", e.entity, e.value)),
                    Some((_, _, labels)) => match &e.labels {
                        Some(want) if want.is_empty() && !labels.is_empty() => {
                            problems.push(format!("{:?} has unexpected labels {labels:?}", e.value))
                        }
                        Some(want) => {
                            for l in want {
                                if !labels.contains(l) {
                                    problems.push(format!("{:?} lacks label {l}", e.value));
                                }
                            }
                        }
                        None => {}
                    },
                }
            }
            for (entity, value, _) in &got {
                if !case
                    .expect
                    .iter()
                    .any(|e| e.entity == *entity && e.value == *value)
                {
                    problems.push(format!("unexpected {entity} {value:?}"));
                }
            }
            if !problems.is_empty() {
                failures.push(format!(
                    "{name}:{} ({}): {}",
                    i + 1,
                    case.note,
                    problems.join("; ")
                ));
            }
        }
    }
    assert!(
        cases > 100,
        "expected the fixture files to hold more cases, found {cases}"
    );
    assert!(
        failures.is_empty(),
        "{} of {cases} fixtures failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
