from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from . import _veil
from ._models import download_model
from ._types import Decision, Detection, Enforcement, Finding, Profile, Protection


class Veil:
    """Finds personal information in text and protects it under a policy.

    Build one and reuse it: building loads the country packs, the policy and, if you ask
    for one, the model. Every call is thread-safe and releases the GIL while it scans.

    ``country`` limits detection to one country's pack, such as ``"GH"``; every pack applies
    when it's ``None``. ``policy`` is the name of a built-in policy, or a path to a policy
    written in YAML; ``policy_yaml`` takes the YAML itself. ``model`` adds Veil's contextual
    model, which finds names, addresses given as directions and institutions' own ID
    numbers: pass ``"veil-ner-nano"`` or ``"veil-ner-deep"`` to download it once from
    Hugging Face, or the path of a directory that holds one. With a model, scans run the
    ``hybrid`` profile, rules and model together, unless ``profile`` says otherwise.
    """

    def __init__(
        self,
        *,
        country: str | None = None,
        policy: str | os.PathLike[str] = "default-protection",
        policy_yaml: str | None = None,
        model: str | os.PathLike[str] | None = None,
        profile: Profile | None = None,
        threads: int = 1,
        revision: str = "main",
    ) -> None:
        if policy_yaml is None and isinstance(policy, os.PathLike):
            policy_yaml = Path(policy).read_text(encoding="utf-8")
        self._engine = _veil.Engine(
            country=country,
            policy=None if policy_yaml is not None else str(policy),
            policy_yaml=policy_yaml,
            model_dir=_model_dir(model, revision),
            profile_name=profile,
            threads=threads,
        )

    @property
    def profile(self) -> Profile:
        """The profile scans use unless they ask for another."""
        return self._engine.profile  # type: ignore[return-value]

    @property
    def policy(self) -> str:
        """The policy's name and revision, such as ``default-protection@2026-11-04``."""
        return self._engine.policy

    def detect(self, text: str, *, context: Mapping[str, str] | None = None, profile: Profile | None = None) -> Detection:
        """Finds personal information in ``text`` without changing it."""
        return self.detect_all([_text(text)], context=context, profile=profile)[0]

    def detect_all(
        self, texts: Iterable[str], *, context: Mapping[str, str] | None = None, profile: Profile | None = None
    ) -> list[Detection]:
        """Runs :meth:`detect` on several texts in one call."""
        segments = [_text(t) for t in texts]
        raw = json.loads(self._engine.detect(segments, context_json=_context(context), profile_name=profile))
        warnings = tuple(raw["warnings"])
        return [
            Detection(
                findings=tuple(Finding._from(f) for f in segment["findings"]),
                profile=raw["profile_used"],
                warnings=warnings,
            )
            for segment in raw["segments"]
        ]

    def protect(
        self,
        text: str,
        *,
        context: Mapping[str, str] | None = None,
        enforcement: Enforcement | None = None,
        restore: bool = False,
        profile: Profile | None = None,
    ) -> Protection:
        """Applies the policy to ``text``.

        ``context`` describes the request for policy rules that match on it, with any of
        ``destination_provider``, ``application``, ``environment`` and ``purpose``.
        ``enforcement`` decides what happens when a scan can't complete: ``closed`` blocks,
        ``open`` lets the text through with a warning, and ``rules_fallback`` carries on with
        the rules alone. ``restore=True`` keeps the original values in memory so
        :meth:`Protection.restore` can put them back into a reply.
        """
        return self.protect_all(
            [_text(text)], context=context, enforcement=enforcement, restore=restore, profile=profile
        )[0]

    def protect_all(
        self,
        texts: Iterable[str],
        *,
        context: Mapping[str, str] | None = None,
        enforcement: Enforcement | None = None,
        restore: bool = False,
        profile: Profile | None = None,
    ) -> list[Protection]:
        """Protects several texts together, such as the messages of one chat.

        The same value gets the same placeholder in every text, and a block in any text
        blocks them all.
        """
        segments = [_text(t) for t in texts]
        raw = json.loads(
            self._engine.protect(
                segments,
                context_json=_context(context),
                enforcement_name=enforcement,
                restore=restore,
                profile_name=profile,
            )
        )
        policy = f"{raw['policy']['name']}@{raw['policy']['revision']}"
        warnings = tuple(raw["warnings"])
        values = raw.get("restore")
        return [
            Protection(
                text=segment["output"],
                blocked=raw["blocked"],
                decisions=tuple(Decision._from(d) for d in segment["decisions"]),
                policy=policy,
                profile=raw["profile_used"],
                warnings=warnings,
                _values=values,
            )
            for segment in raw["segments"]
        ]

    def __repr__(self) -> str:
        return f"Veil(policy={self.policy!r}, profile={self.profile!r})"


def builtin_policies() -> list[dict[str, Any]]:
    """The built-in policies, with each one's name, revision and description."""
    return json.loads(_veil.builtin_policies())


def entities() -> list[dict[str, Any]]:
    """Every kind of personal information Veil can report, with its categories and sensitivity."""
    return json.loads(_veil.entities())


def countries() -> list[dict[str, Any]]:
    """The country packs in this build and their versions."""
    return json.loads(_veil.countries())


def validate_policy(yaml: str) -> list[dict[str, str]]:
    """Checks a policy written in YAML and returns every problem with its path. An empty
    list means the policy is valid."""
    return json.loads(_veil.validate_policy(yaml))["errors"]


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Veil scans text; got {type(value).__name__}")
    return value


def _context(context: Mapping[str, str] | None) -> str | None:
    return None if context is None else json.dumps(dict(context))


def _model_dir(model: str | os.PathLike[str] | None, revision: str) -> str | None:
    if model is None:
        return None
    if os.path.isdir(model):
        return os.fspath(model)
    if isinstance(model, os.PathLike):
        raise FileNotFoundError(f"there is no model directory at {os.fspath(model)}")
    return os.fspath(download_model(model, revision=revision))
