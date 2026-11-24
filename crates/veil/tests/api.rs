//! The request and response contract shared by the server and the C ABI.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use veil::api::{self, ApiError, PolicySpec, ProtectRequest};
use veil::{DetectionContext, Enforcement, Finding, Policy, Veil};
use veil_core::{DetectionError, DetectionMethod, Detector, DetectorInfo};

fn request(segments: &[&str], yaml: Option<&str>) -> ProtectRequest {
    ProtectRequest {
        segments: segments.iter().map(|s| s.to_string()).collect(),
        country: Some("GH".into()),
        policy: yaml.map_or_else(PolicySpec::default, |y| PolicySpec::Yaml { yaml: y.into() }),
        context: Default::default(),
        enforcement: None,
        restore: false,
        profile: None,
    }
}

const TOKENIZE: &str = "version: 1\nname: tokenize-all\ndefault_action: tokenize\n";

fn run(
    veil: &Veil,
    req: &ProtectRequest,
    allow_restore: bool,
) -> Result<api::ProtectResponse, ApiError> {
    let policy = api::compile_policy(&req.policy)?;
    veil.protect_segments(req, &policy, allow_restore)
}

#[test]
fn numbering_is_shared_across_segments() {
    let veil = Veil::builder().country("gh").build().unwrap();
    let mut req = request(
        &[
            "Call 024 123 4567 now",
            "Again, 024 123 4567 or 020 765 4321",
        ],
        Some(TOKENIZE),
    );
    req.restore = true;
    let out = run(&veil, &req, true).unwrap();
    assert_eq!(
        out.segments[0].output.as_deref(),
        Some("Call [GH_MOBILE_NUMBER_1] now")
    );
    assert_eq!(
        out.segments[1].output.as_deref(),
        Some("Again, [GH_MOBILE_NUMBER_1] or [GH_MOBILE_NUMBER_2]")
    );
    let restore = out.restore.unwrap();
    assert_eq!(
        restore.get("[GH_MOBILE_NUMBER_1]").map(String::as_str),
        Some("024 123 4567")
    );
    assert_eq!(out.summary.findings, 3);
    assert_eq!(out.summary.by_action.get("TOKENIZE"), Some(&3));
}

#[test]
fn restore_needs_the_request_and_the_host() {
    let veil = Veil::builder().country("gh").build().unwrap();
    let mut req = request(&["Call 024 123 4567"], Some(TOKENIZE));
    assert!(
        run(&veil, &req, true).unwrap().restore.is_none(),
        "not asked for"
    );
    req.restore = true;
    let refused = run(&veil, &req, false).unwrap();
    assert!(refused.restore.is_none());
    assert!(refused.warnings.iter().any(|w| w.contains("doesn't allow")));
}

#[test]
fn one_blocked_segment_blocks_every_segment() {
    let veil = Veil::builder().country("gh").build().unwrap();
    let req = request(
        &["Call 024 123 4567", "My Ghana Card is GHA-723451904-3"],
        None,
    );
    let out = run(&veil, &req, true).unwrap();
    assert!(out.blocked);
    assert!(out.segments.iter().all(|s| s.output.is_none()));
    assert_eq!(out.policy.name.as_deref(), Some("default-protection"));
}

#[test]
fn responses_never_carry_values_without_restore() {
    let veil = Veil::builder().country("gh").build().unwrap();
    let out = run(
        &veil,
        &request(&["Send the MoMo to 024 123 4567, ama@example.com"], None),
        true,
    )
    .unwrap();
    let json = serde_json::to_string(&out).unwrap();
    assert!(
        !json.contains("123 4567") && !json.contains("ama@example.com"),
        "{json}"
    );
    assert!(json.contains("\"offset_unit\":\"utf8_byte\""));
}

#[test]
fn invalid_policies_report_every_problem() {
    let err = api::compile_policy(&PolicySpec::Yaml {
        yaml: "version: 2\nname: ''\n".into(),
    })
    .unwrap_err();
    let ApiError::InvalidPolicy(issues) = err else {
        panic!("expected invalid_policy")
    };
    assert!(issues.len() >= 2, "{issues:?}");
    assert!(matches!(
        api::compile_policy(&PolicySpec::Named {
            name: "nope".into()
        }),
        Err(ApiError::InvalidPolicy(_))
    ));
}

#[test]
fn segment_limits_are_checked() {
    assert!(matches!(
        api::check_segments(&[], 10),
        Err(ApiError::BadRequest(_))
    ));
    let many: Vec<String> = (0..65).map(|_| "a".to_string()).collect();
    assert!(matches!(
        api::check_segments(&many, 1000),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        api::check_segments(&["a".repeat(11)], 10),
        Err(ApiError::InputTooLarge {
            size: 11,
            limit: 10
        })
    ));
}

#[derive(Debug)]
struct Broken;

impl Detector for Broken {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "broken-v1",
            description: "always fails",
            entity_types: vec![],
            jurisdiction: None,
            method: DetectionMethod::Pattern,
        }
    }
    fn detect(&self, _: &str, _: &DetectionContext) -> Result<Vec<Finding>, DetectionError> {
        Err(DetectionError::new("simulated failure"))
    }
}

#[test]
fn enforcement_decides_what_a_failed_scan_does() {
    let veil = Veil::builder()
        .country("gh")
        .detector(Broken)
        .build()
        .unwrap();
    let policy = Policy::builtin("default-protection").unwrap();
    let mut req = request(&["Call 024 123 4567"], None);
    assert!(matches!(
        veil.protect_segments(&req, &policy, false),
        Err(ApiError::ScanFailed(_))
    ));
    req.enforcement = Some(Enforcement::Open);
    let open = veil.protect_segments(&req, &policy, false).unwrap();
    assert_eq!(
        open.segments[0].output.as_deref(),
        Some("Call 024 123 4567")
    );
    assert!(open.warnings.iter().any(|w| w.contains("wasn't scanned")));
}

#[test]
fn the_taxonomy_describes_every_entity_a_detector_reports() {
    let veil = Veil::builder().build().unwrap();
    let known: Vec<String> = api::entities().into_iter().map(|e| e.code).collect();
    for code in veil.entity_types() {
        assert!(
            known.contains(&code),
            "{code} is missing from crates/veil/taxonomy.toml"
        );
    }
    assert!(api::countries().iter().any(|c| c.code == "GH"));
    assert!(api::builtin_policies()
        .iter()
        .any(|p| p.name == "default-protection" && !p.description.is_empty()));
}

#[test]
fn a_profile_without_a_model_is_refused_unless_rules_fallback_is_asked_for() {
    let veil = Veil::builder()
        .country("gh")
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    let mut req = request(&["call 024 123 4567"], None);
    req.profile = Some(veil::Profile::Hybrid);
    assert!(matches!(
        run(&veil, &req, false),
        Err(ApiError::ProfileUnavailable(veil::Profile::Hybrid))
    ));

    req.enforcement = Some(Enforcement::RulesFallback);
    let out = run(&veil, &req, false).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(out.profile_used, veil::Profile::Rules);
    assert!(out
        .warnings
        .iter()
        .any(|w| w.contains("only the rules ran")));

    let detect = api::DetectRequest {
        segments: vec!["x".into()],
        country: None,
        context: Default::default(),
        profile: Some(veil::Profile::Nano),
    };
    assert!(matches!(
        veil.detect_segments(&detect),
        Err(ApiError::ProfileUnavailable(veil::Profile::Nano))
    ));
}
