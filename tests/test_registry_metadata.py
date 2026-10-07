"""Guards for the MCP Registry listing: these only fail at publish time otherwise."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


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
