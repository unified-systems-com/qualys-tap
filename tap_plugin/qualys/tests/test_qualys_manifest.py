"""The plugin validates at structure and strict levels (new-plugin Step 9).

Runs ``validate_plugin`` against the package directory (tap_plugin/qualys), which resolves the same from an
editable checkout and an installed wheel. The loads and runs levels need a booted plugin and are exercised
by booting the ``ci`` record. Nothing here re-implements what the validation system already checks.
"""

from pathlib import Path

import pytest

from tap_plugins.validate.service import validate_plugin

PACKAGE_DIR = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("strict", [False, True], ids=["structure", "strict"])
def test_plugin_validates(strict: bool) -> None:
    result = validate_plugin(PACKAGE_DIR, level="structure", strict=strict)
    if not result.ok:
        raise AssertionError(result.to_human())
