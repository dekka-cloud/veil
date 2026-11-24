"""Fetching Veil's open models from Hugging Face.

A model is three files, ``manifest.yaml``, ``tokenizer.json`` and ``model.onnx``, kept in a
cache directory after the first download. Veil checks every file against the SHA-256 in
the manifest when it loads them, so a damaged or tampered download fails loudly.
"""

from __future__ import annotations

import os
import tempfile
import urllib.request
from pathlib import Path

from ._veil import __version__

MODELS: dict[str, str] = {
    "veil-ner-nano": "dekka-cloud/veil-ner-nano",
    "veil-ner-deep": "dekka-cloud/veil-ner-deep",
}
"""Veil's published models and the Hugging Face repositories they live in."""

_FILES = ("manifest.yaml", "tokenizer.json", "model.onnx")


def cache_dir() -> Path:
    """Where downloaded models are kept: ``$DEKKA_VEIL_CACHE``, else ``dekka-veil`` in the
    user's cache directory."""
    if configured := os.environ.get("DEKKA_VEIL_CACHE"):
        return Path(configured)
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(Path.home(), ".cache")
    return Path(base) / "dekka-veil"


def download_model(name: str = "veil-ner-nano", *, revision: str = "main", cache: str | os.PathLike[str] | None = None) -> Path:
    """Downloads a model once and returns the directory that holds it.

    ``name`` is one of :data:`MODELS` or any Hugging Face repository id with the same three
    files. ``revision`` is a branch, tag or commit; pin a commit to make a deployment
    reproducible. Files already in the cache aren't fetched again.
    """
    repo = MODELS.get(name, name)
    if repo.count("/") != 1:
        known = ", ".join(MODELS)
        raise ValueError(f"there is no model called {name!r}; use one of {known}, or a Hugging Face repository id")
    target = Path(cache) if cache is not None else cache_dir()
    target = target / repo.replace("/", "--") / revision
    target.mkdir(parents=True, exist_ok=True)
    endpoint = os.environ.get("HF_ENDPOINT", "https://huggingface.co").rstrip("/")
    for file in _FILES:
        if not (target / file).is_file():
            _fetch(f"{endpoint}/{repo}/resolve/{revision}/{file}", target / file)
    return target


def _fetch(url: str, path: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": f"dekka-veil/{__version__}"})
    # Write beside the destination and rename, so an interrupted download never leaves a
    # partial file that looks complete.
    fd, partial = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(request, timeout=60) as response:
            while chunk := response.read(1 << 20):
                out.write(chunk)
        os.replace(partial, path)
    except BaseException:
        Path(partial).unlink(missing_ok=True)
        raise
