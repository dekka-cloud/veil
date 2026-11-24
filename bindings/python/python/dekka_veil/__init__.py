"""Dekka Veil finds personal information in text and protects it before the text goes
anywhere it shouldn't, such as a prompt on its way to an AI model.

>>> from dekka_veil import Veil
>>> Veil().protect("Please call 024 123 4567").text
'Please call 024 *** 4567'
"""

from ._core import Veil, builtin_policies, countries, entities, validate_policy
from ._models import MODELS, cache_dir, download_model
from ._types import Decision, Detection, Finding, Protection
from ._veil import VeilError, __version__

__all__ = [
    "MODELS",
    "Decision",
    "Detection",
    "Finding",
    "Protection",
    "Veil",
    "VeilError",
    "__version__",
    "builtin_policies",
    "cache_dir",
    "countries",
    "download_model",
    "entities",
    "validate_policy",
]
