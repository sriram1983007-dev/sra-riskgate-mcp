"""Every file the tests need must ship in the sdist (Audit #12, Finding 1)."""
import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_every_test_file_is_in_the_manifest():
    patterns = [line.split()[2:] for line in (ROOT / "MANIFEST.in").read_text().splitlines()
                if line.startswith("recursive-include tests")]
    globs = [g for p in patterns for g in p]
    for f in (ROOT / "tests").rglob("*"):
        if f.is_file() and "__pycache__" not in f.parts:
            assert any(fnmatch.fnmatch(f.name, g) for g in globs), f"{f.relative_to(ROOT)} is not shipped in the sdist"
