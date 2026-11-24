"""The objects Veil returns.

None of them holds a personal value. A finding or decision says where something is, what it
is and how sure Veil is, so it's safe to log. Slice the original text with ``start`` and
``end`` when you need the value itself.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

Action = Literal["DETECT", "ALLOW", "MASK", "REDACT", "TOKENIZE", "BLOCK"]
Validation = Literal["INVALID", "UNVERIFIED", "NOT_APPLICABLE", "VALID_FORMAT", "VALID"]
Evidence = Literal["ISSUER_CONFIRMED", "INTERNATIONAL_STANDARD", "SECONDARY", "UNPUBLISHED"]
Profile = Literal["rules", "nano", "hybrid"]
Enforcement = Literal["closed", "open", "rules_fallback"]


@dataclass(frozen=True, slots=True)
class Finding:
    """Something Veil detected. ``text[start:end]`` is the value."""

    entity_type: str
    start: int
    end: int
    confidence: float
    detector: str
    validation: Validation
    evidence: Evidence | None
    family: str
    categories: tuple[str, ...]
    sensitivity: str
    jurisdiction: str | None

    @classmethod
    def _from(cls, raw: Mapping[str, Any]) -> Finding:
        return cls(
            entity_type=raw["entity_type"],
            start=raw["span"]["start"],
            end=raw["span"]["end"],
            confidence=raw["confidence"],
            detector=raw["detector"],
            validation=raw["validation"],
            evidence=raw.get("evidence"),
            family=raw["family"],
            categories=tuple(raw.get("categories", ())),
            sensitivity=raw["sensitivity"],
            jurisdiction=raw.get("jurisdiction"),
        )


@dataclass(frozen=True, slots=True)
class Decision:
    """What the policy did with one finding. ``start`` and ``end`` index the original text."""

    entity_type: str
    start: int
    end: int
    action: Action
    rule: str | None
    detector: str
    validation: Validation
    evidence: Evidence | None
    confidence: float

    @classmethod
    def _from(cls, raw: Mapping[str, Any]) -> Decision:
        rule = raw.get("rule")
        return cls(
            entity_type=raw["entity_type"],
            start=raw["span"]["start"],
            end=raw["span"]["end"],
            action=raw["action"],
            rule=rule.get("id") if rule else None,
            detector=raw["detector"],
            validation=raw["validation"],
            evidence=raw.get("evidence"),
            confidence=raw["confidence"],
        )


@dataclass(frozen=True, slots=True)
class Detection:
    """What Veil found in one text."""

    findings: tuple[Finding, ...]
    profile: Profile
    warnings: tuple[str, ...]

    def __iter__(self):
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)


@dataclass(frozen=True, slots=True)
class Protection:
    """One text after the policy was applied.

    ``text`` is the protected text, or ``None`` when the policy blocked the request. When
    texts are protected together, one block blocks them all.
    """

    text: str | None
    blocked: bool
    decisions: tuple[Decision, ...]
    policy: str
    profile: Profile
    warnings: tuple[str, ...]
    _values: Mapping[str, str] | None = field(default=None, repr=False, compare=False)

    def restore(self, text: str) -> str:
        """Puts the original values back in place of this protection's placeholders.

        Use it on a reply that echoes placeholders, such as an AI model's answer. It needs
        ``restore=True`` on the call that protected the text, and a policy that tokenises.
        """
        if self._values is None:
            raise ValueError("this protection holds no values to restore; protect with restore=True")
        if not self._values:
            return text
        # One pass over the text, so a restored value that looks like a placeholder stays as it is.
        values = self._values
        pattern = re.compile("|".join(re.escape(p) for p in values))
        return pattern.sub(lambda m: values[m.group(0)], text)
