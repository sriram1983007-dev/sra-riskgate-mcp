"""Guards for the MCP Registry listing: these only fail at publish time otherwise."""
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if not (ROOT / "server.json").exists() or not (ROOT / "pyproject.toml").exists():
    pytest.skip("registry metadata files are only checked in a full source checkout", allow_module_level=True)


def _pyproject_version():
    return re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)


def test_versions_agree():
    server = json.loads((ROOT / "server.json").read_text())
    import sra_riskgate_mcp
    versions = {_pyproject_version(), server["version"], server["packages"][0]["version"], sra_riskgate_mcp.__version__}
    assert len(versions) == 1, versions


def test_readme_carries_mcp_name_marker():
    server = json.loads((ROOT / "server.json").read_text())
    assert f"mcp-name: {server['name']}" in (ROOT / "README.md").read_text()


def test_registry_constraints():
    server = json.loads((ROOT / "server.json").read_text())
    assert len(server["description"]) <= 100
    assert server["name"].startswith("io.github.sriram1983007-dev/")
    assert server["packages"][0]["identifier"] == "sra-riskgate-mcp"
    assert server["packages"][0]["transport"]["type"] == "stdio"


def test_every_setting_the_server_reads_is_declared():
    """0.9.1: server.json lists every SRA_ environment variable the code reads, so clients can offer them."""
    src = "".join(p.read_text() for p in (ROOT / "src" / "sra_riskgate_mcp").glob("*.py"))
    used = set(re.findall(r'"(SRA_[A-Z_]+)"', src))
    used |= {f"{name}_FILE" for name in re.findall(r'_address_env\("(SRA_[A-Z_]+)"\)', src)}
    server = json.loads((ROOT / "server.json").read_text())
    declared = {e["name"] for e in server["packages"][0]["environmentVariables"]}
    assert used - declared == set()
    secret = {e["name"] for e in server["packages"][0]["environmentVariables"] if e["isSecret"]}
    assert secret == {"SRA_API_KEY"}
