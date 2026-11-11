"""0.14.0: SRA_EXTRA_TOKENS registers US-dollar stablecoins the SDK does not list (sra-riskgate 1.1.0)."""
import json

import pytest
from sra_riskgate.chains import _reset_registry

from test_server import call

ME, YOU, OTHER = "0x" + "a" * 40, "0x" + "b" * 40, "0x" + "c" * 40
CHAIN, TOKEN = 7777777, "0x" + "12" * 20
ENTRY = {"symbol": "TUSD8", "chain_id": CHAIN, "contract": TOKEN, "decimals": 6}
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@pytest.fixture(autouse=True)
def clean_registry():
    _reset_registry()
    yield
    _reset_registry()


def transfer(to=YOU, atomic=20_000_000):
    return "0xa9059cbb" + to.lower()[2:].zfill(64) + format(atomic, "064x")


def rules(**kw):
    args = dict(chain_id=CHAIN, sender=ME, recipient=YOU, amount_usdc=20, peg_deviation_pct=0.0, token="TUSD8")
    args.update(kw)
    return call("check_payment_rules", args)


def tx(data=None):
    return call("check_transaction", dict(chain_id=CHAIN, sender=ME, to=TOKEN, data=data or transfer(),
                                          peg_deviation_pct=0.0))


def test_unregistered_token_is_held():
    assert rules()["flags"] == ["unsupported_asset"]
    assert tx()["flags"] == ["UNSUPPORTED_CHAIN"]


def test_registered_but_not_enabled_is_held(monkeypatch):
    monkeypatch.setenv("SRA_EXTRA_TOKENS", json.dumps([ENTRY]))
    out = rules()
    assert out["flags"] == ["unsupported_asset"] and "TUSD8 is not enabled" in out["explanation"]


def test_registered_and_enabled(monkeypatch):
    monkeypatch.setenv("SRA_EXTRA_TOKENS", json.dumps(ENTRY))  # a single object works too
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "USDC,TUSD8")
    assert rules()["decision"] == "approve"
    out = tx()
    assert out["decision"] == "approve" and out["decoded"] == {"recipient": YOU, "token": "TUSD8", "amount": "20"}
    approve = "0x095ea7b3" + OTHER[2:].zfill(64) + "f" * 64
    assert tx(approve)["flags"] == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]


def test_from_file(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps([ENTRY]))
    monkeypatch.setenv("SRA_EXTRA_TOKENS_FILE", str(f))
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "TUSD8")
    assert rules()["decision"] == "approve"


def test_settlement_and_allowances_by_symbol(monkeypatch):
    monkeypatch.setenv("SRA_EXTRA_TOKENS", json.dumps([ENTRY]))
    word = lambda a: "0x" + a.lower()[2:].zfill(64)
    rc = {"status": "0x1", "blockNumber": "0x1", "logs": [
        {"address": TOKEN, "topics": [TRANSFER_TOPIC, word(ME), word(YOU)], "data": "0x" + format(2_500_000, "064x")}]}
    out = call("verify_settlement", dict(receipt=rc, chain_id=CHAIN, payer=ME, payee=YOU, amount_usdc="2.5",
                                         token="TUSD8"))
    assert out["verified"] is True and "TUSD8" in out["explanation"]
    out = call("check_allowances", dict(owner=ME, allowances={OTHER: str(2**256 - 1)}, token="TUSD8", chain_id=CHAIN))
    assert out["flags"] == ["UNLIMITED_ALLOWANCE"]


@pytest.mark.parametrize("raw", ["not json", "42", json.dumps([{"symbol": "X"}]),
                                 json.dumps([{**ENTRY, "extra": 1}]), json.dumps([{**ENTRY, "decimals": "6"}]),
                                 json.dumps([{**ENTRY, "symbol": "USDC"}]),
                                 json.dumps([{**ENTRY, "chain_id": 8453,
                                              "contract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}])])
def test_bad_setting_fails_closed(monkeypatch, raw):
    monkeypatch.setenv("SRA_EXTRA_TOKENS", raw)
    assert rules(token="USDC", chain_id=8453)["flags"] == ["configuration_error"]
    assert tx()["flags"] == ["configuration_error"]
    v = call("verify_settlement", dict(receipt={"status": "0x1", "logs": []}, chain_id=8453, payer=ME, payee=YOU,
                                       amount_usdc="1"))
    assert v["verified"] is False and v["flags"] == ["CONFIGURATION_ERROR"]
    assert call("check_allowances", dict(owner=ME, allowances={OTHER: "1"}))["decision"] == "hold"


def test_missing_file_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("SRA_EXTRA_TOKENS_FILE", str(tmp_path / "nope.json"))
    assert rules(token="USDC", chain_id=8453)["flags"] == ["configuration_error"]
