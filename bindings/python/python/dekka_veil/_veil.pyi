"""The native extension. Use the public API in ``dekka_veil`` instead."""

__version__: str

class VeilError(Exception):
    """Raised when Veil can't build or can't answer a request."""

class Engine:
    def __init__(
        self,
        *,
        country: str | None = ...,
        policy: str | None = ...,
        policy_yaml: str | None = ...,
        model_dir: str | None = ...,
        profile_name: str | None = ...,
        threads: int = ...,
    ) -> None: ...
    def protect(
        self,
        segments: list[str],
        *,
        context_json: str | None = ...,
        enforcement_name: str | None = ...,
        restore: bool = ...,
        profile_name: str | None = ...,
    ) -> str: ...
    def detect(self, segments: list[str], *, context_json: str | None = ..., profile_name: str | None = ...) -> str: ...
    @property
    def profile(self) -> str: ...
    @property
    def policy(self) -> str: ...

def builtin_policies() -> str: ...
def entities() -> str: ...
def countries() -> str: ...
def validate_policy(yaml: str) -> str: ...
