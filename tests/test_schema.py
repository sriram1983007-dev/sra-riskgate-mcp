import asyncio

from sra_riskgate_mcp import __version__
from sra_riskgate_mcp.server import mcp


def _tools():
    return asyncio.run(mcp.list_tools())


def _schema(tool):  # mcp 1.x: inputSchema, mcp 2.x: input_schema
    return getattr(tool, "inputSchema", None) or getattr(tool, "input_schema")


def test_every_parameter_has_a_description():
    tools = _tools()
    assert {t.name for t in tools} == {"check_address_sanctions", "check_payment_rules", "check_x402_payment", "check_transaction", "check_x402_authorization", "check_payment_with_model"}
    for t in tools:
        for name, prop in _schema(t)["properties"].items():
            assert prop.get("description"), f"{t.name}.{name} has no description"


def test_units_are_explained():
    props = {t.name: _schema(t)["properties"] for t in _tools()}
    assert "whole USDC" in props["check_payment_rules"]["amount_usdc"]["description"]
    assert "smallest unit" in props["check_x402_payment"]["amount"]["description"]


def test_version_matches_package():
    import importlib.metadata as md
    assert __version__ == md.version("sra-riskgate-mcp")
