from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import dekka_veil
from dekka_veil import Veil, VeilError

# A 1 KB test model that tags a handful of words, not trained weights. It exercises the
# model path without a download.
TINY_MODEL = Path(__file__).parents[3] / "crates/veil-inference/tests/fixtures/tiny"

TOKENIZE = """
version: 1
name: support-desk
revision: "1"
default_action: tokenize
rules: []
"""


@pytest.fixture(scope="module")
def veil() -> Veil:
    return Veil(country="GH")


def test_the_default_policy_masks_phone_numbers_and_redacts_the_rest(veil: Veil) -> None:
    out = veil.protect("Please call 024 123 4567 or write to ama@example.com")
    assert out.text == "Please call 024 *** 4567 or write to [EMAIL_ADDRESS]"
    assert not out.blocked
    assert [(d.entity_type, d.action) for d in out.decisions] == [
        ("GH_MOBILE_NUMBER", "MASK"),
        ("EMAIL_ADDRESS", "REDACT"),
    ]
    assert out.policy.startswith("default-protection@")
    assert out.profile == "rules"


def test_a_ghana_card_pin_blocks_every_text_protected_with_it(veil: Veil) -> None:
    first, second = veil.protect_all(["My Ghana Card is GHA-123456789-0", "Thanks"])
    assert first.blocked and second.blocked
    assert first.text is None and second.text is None
    assert first.decisions[0].rule == "block-ghana-card"


def test_offsets_index_python_strings_even_after_wide_characters(veil: Veil) -> None:
    text = "Ɛyɛ 🙂 me number yɛ 024 123 4567"
    (finding,) = veil.detect(text).findings
    assert text[finding.start : finding.end] == "024 123 4567"
    (decision,) = veil.protect(text).decisions
    assert text[decision.start : decision.end] == "024 123 4567"


def test_findings_describe_what_was_found_and_never_hold_the_value(veil: Veil) -> None:
    detection = veil.detect("Send the MoMo to 024 123 4567")
    assert len(detection) == 1
    finding = next(iter(detection))
    assert finding.entity_type == "GH_MOBILE_NUMBER"
    assert finding.jurisdiction == "GH"
    assert finding.validation == "VALID_FORMAT"
    assert "024" not in repr(finding)


def test_a_custom_policy_can_tokenise_and_restore_values_in_a_reply() -> None:
    veil = Veil(country="GH", policy_yaml=TOKENIZE)
    out = veil.protect("Email ama@example.com about it", restore=True)
    assert out.text == "Email [EMAIL_ADDRESS_1] about it"
    assert out.restore("I've written to [EMAIL_ADDRESS_1].") == "I've written to ama@example.com."


def test_restoring_needs_the_values_to_have_been_kept() -> None:
    out = Veil(policy_yaml=TOKENIZE).protect("Email ama@example.com")
    with pytest.raises(ValueError, match="restore=True"):
        out.restore("[EMAIL_ADDRESS_1]")


def test_a_restored_value_that_looks_like_a_placeholder_stays_as_it_is() -> None:
    values = {"[EMAIL_ADDRESS_1]": "[EMAIL_ADDRESS_2]", "[EMAIL_ADDRESS_2]": "ama@example.com"}
    out = dekka_veil.Protection("x", False, (), "p@1", "rules", (), values)
    assert out.restore("[EMAIL_ADDRESS_1] and [EMAIL_ADDRESS_2]") == "[EMAIL_ADDRESS_2] and ama@example.com"


@pytest.mark.parametrize("revision", ["../../tmp/evil", "..", "/etc", "a//b", "main/..", "a\\b", ""])
def test_a_revision_cannot_lead_out_of_the_model_cache(tmp_path: Path, revision: str) -> None:
    with pytest.raises(ValueError, match="isn't a branch, tag or commit"):
        dekka_veil.download_model("veil-ner-nano", revision=revision, cache=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_policy_file_is_read_from_its_path(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(TOKENIZE, encoding="utf-8")
    assert Veil(policy=path).policy == "support-desk@1"


def test_problems_in_a_policy_are_reported_with_their_paths() -> None:
    errors = dekka_veil.validate_policy("version: 1\nname: x\nrules:\n  - action: shout\n")
    assert errors
    assert all("path" in e and "message" in e for e in errors)
    assert dekka_veil.validate_policy(TOKENIZE) == []


def test_mistakes_are_reported_as_veil_errors() -> None:
    with pytest.raises(VeilError, match="no built-in policy"):
        Veil(policy="no-such-policy")
    with pytest.raises(VeilError):
        Veil().protect("hello", context={"colour": "blue"})
    with pytest.raises(VeilError, match="profile"):
        Veil().detect("hello", profile="hybrid")


def test_only_text_is_scanned() -> None:
    with pytest.raises(TypeError, match="got bytes"):
        Veil().protect(b"024 123 4567")  # type: ignore[arg-type]


def test_a_model_directory_turns_on_the_hybrid_profile() -> None:
    veil = Veil(model=TINY_MODEL)
    assert veil.profile == "hybrid"
    text = "call Ama Mensah , Kofi lives in Osu ."
    names = [text[f.start : f.end] for f in veil.detect(text).findings if f.entity_type == "PERSON_NAME"]
    assert names == ["Ama Mensah", "Kofi"]
    assert Veil(model=TINY_MODEL, profile="rules").detect(text).findings == ()


def test_a_missing_model_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        Veil(model=tmp_path / "missing")


def test_one_veil_serves_many_threads_at_once(veil: Veil) -> None:
    texts = [f"Call 024 123 45{i:02d}" for i in range(64)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outputs = list(pool.map(lambda t: veil.protect(t).text, texts))
    assert outputs == [f"Call 024 *** 45{i:02d}" for i in range(64)]


def test_the_catalogue_lists_policies_entities_and_countries() -> None:
    assert any(p["name"] == "default-protection" for p in dekka_veil.builtin_policies())
    assert any(e["code"] == "GH_GHANA_CARD_PIN" for e in dekka_veil.entities())
    assert any(c["code"] == "GH" for c in dekka_veil.countries())
