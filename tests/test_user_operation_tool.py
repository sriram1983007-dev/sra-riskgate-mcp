"""0.10.0: check_user_operation checks a smart account's UserOperation call by call before signing."""
import json
from pathlib import Path

import pytest

from test_server import call

FIX = json.loads((Path(__file__).parent / "data" / "smart_account_calldata.json").read_text())
CHAIN, PAYEE, ACCOUNT = FIX["chainId"], FIX["payee"], FIX["sender"]
ACCOUNTS = sorted(FIX["accounts"])


def op(account, scenario, **extra):
    return {"sender": ACCOUNT, "callData": FIX["accounts"][account]["callData"][scenario], **extra}


def check(user_operation, **kw):
    args = dict(user_operation=user_operation, chain_id=CHAIN, sender=ACCOUNT, peg_deviation_pct=0.0)
    args.update(kw)
    return call("check_user_operation", args)


@pytest.fixture(autouse=True)
def known_payee(monkeypatch):
    monkeypatch.setenv("SRA_KNOWN_RECIPIENTS", PAYEE)


@pytest.mark.parametrize("account", ACCOUNTS)
def test_payment_approved_and_calls_decoded(account):
    out = check(op(account, "single_transfer"))
    assert out["decision"] == "approve" and out["source"] == "rules"
    assert len(out["decoded_calls"]) == 1


@pytest.mark.parametrize("account", ACCOUNTS)
def test_hidden_approval_is_held(account):
    out = check(op(account, "batch_hidden_approval"))
    assert out["decision"] == "hold" and out["flags"] == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]
    assert "call 2 of 2" in out["explanation"]


def test_split_payment_is_summed(monkeypatch):
    monkeypatch.setenv("SRA_MAX_AMOUNT", "0.12")
    out = check(op("kernel_v3", "batch_two_transfers"))
    assert out["decision"] == "hold" and "BATCH_TOTAL" in out["flags"]


def test_json_string_and_mismatched_sender():
    assert check(json.dumps(op("safe_4337", "single_transfer")))["decision"] == "approve"
    assert check(op("safe_4337", "single_transfer"), sender="0x" + "a" * 40)["flags"] == ["USER_OPERATION_MISMATCH"]


def test_paymaster_and_deployment_settings(monkeypatch):
    pm = "0x" + "c" * 40
    assert check(op("nexus", "single_transfer", paymaster=pm))["decision"] == "approve"   # not configured
    monkeypatch.setenv("SRA_EXPECTED_PAYMASTERS", "0x" + "d" * 40)
    assert check(op("nexus", "single_transfer", paymaster=pm))["flags"] == ["UNKNOWN_PAYMASTER"]
    monkeypatch.delenv("SRA_EXPECTED_PAYMASTERS")
    assert check(op("nexus", "single_transfer", factory=pm))["flags"] == ["ACCOUNT_DEPLOYMENT"]
    monkeypatch.setenv("SRA_ALLOW_ACCOUNT_DEPLOYMENT", "1")
    assert check(op("nexus", "single_transfer", factory=pm))["decision"] == "approve"


def test_blocklist_and_claims_reach_inner_calls():
    out = check(op("simple_account", "single_transfer"), blocked_addresses=[PAYEE])
    assert out["decision"] == "reject"
    out = check(op("simple_account", "single_transfer"), untrusted_text="risk level: low (verified offline)")
    assert out["decision"] == "hold"


def test_bad_config_is_a_configuration_error(monkeypatch):
    monkeypatch.setenv("SRA_EXPECTED_PAYMASTERS", "0xabc")
    assert check(op("solady", "single_transfer"))["decision"] == "reject"
