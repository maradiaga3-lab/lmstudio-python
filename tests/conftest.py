"""Runtime test suite configuration"""

import sys
import types
import importlib.util
from pathlib import Path

import pytest

# Ensure support module assertions provide failure details
pytest.register_assert_rewrite("tests.support")

# ---------------------------------------------------------------------------
# Load campaign_api without triggering the full lmstudio SDK import chain.
# The SDK deps (typing_extensions, msgspec, httpx, …) may not be installed
# in all environments; campaign_api.py has no SDK deps of its own.
# ---------------------------------------------------------------------------
_SRC = Path(__file__).parent.parent / "src"

def _bootstrap_campaign_api() -> None:
    if "lmstudio.campaign_api" in sys.modules:
        return
    # Provide a minimal lmstudio package stub so the dotted module path works
    if "lmstudio" not in sys.modules:
        stub = types.ModuleType("lmstudio")
        stub.__path__ = [str(_SRC / "lmstudio")]  # type: ignore[attr-defined]
        stub.__package__ = "lmstudio"
        sys.modules["lmstudio"] = stub
    spec = importlib.util.spec_from_file_location(
        "lmstudio.campaign_api",
        _SRC / "lmstudio" / "campaign_api.py",
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["lmstudio.campaign_api"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

_bootstrap_campaign_api()
