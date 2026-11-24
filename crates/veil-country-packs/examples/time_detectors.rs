//! Times each detector on a pathological input. Run with
//! `cargo run --release --example time_detectors -- <file>`.

// Tests and examples may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use std::time::Instant;
use veil_core::DetectionContext;

fn main() {
    let path = std::env::args().nth(1).expect("give a file");
    let text = std::fs::read_to_string(path).expect("read");
    let mut registry = veil_detectors::general();
    veil_country_packs::register("gh", &mut registry).expect("pack");
    let ctx = DetectionContext::default();
    for d in registry.detectors() {
        let t = Instant::now();
        let n = d.detect(&text, &ctx).expect("detect").len();
        println!(
            "{:<24} {:>8.2} ms  {n} findings",
            d.id(),
            t.elapsed().as_secs_f64() * 1000.0
        );
    }
}
