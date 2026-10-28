"""0.9.0: check_circle_wallets_request checks a Circle Wallets API request before it is sent."""
import json

import pytest

from sra_riskgate.chains import USDC_ADDRESSES
from sra_riskgate.sanctions import SanctionsList

from test_server import call

ME, PAYEE, OTHER = "0x" + "a" * 40, "0x2ffb88f73980bc6069c598487396e1e472deb7ee", "0x" + "c" * 40
WALLET_ID = "c4d1da72-111e-4d52-bdbf-2e74a2d803d5"
USDC_ARC = USDC_ADDRESSES[5042002]
SANCTIONED = sorted(SanctionsList.bundled().addresses)[0]


def transfer(**kw):
    body = {"walletId": WALLET_ID, "blockchain": "ARC-TESTNET", "tokenAddress": USDC_ARC,
            "destinationAddress": PAYEE, "amounts": ["2.5"], "feeLevel": "MEDIUM"}
    body.update(kw)
    return body


def circle(op, body, **kw):
    args = dict(operation=op, request=body, sender=ME, peg_deviation_pct=0.1)
    args.update(kw)
    return call("check_circle_wallets_request", args)


def test_usdc_transfer_is_approved():
    out = circle("transfer", transfer())
    assert out["decision"] == "approve" and out["source"] == "rules"


def test_body_as_json_string():
    assert circle("/v1/w3s/developer/transactions/transfer", json.dumps(transfer()))["decision"] == "approve"


def test_payment_checks_apply():
    assert circle("transfer", transfer(destinationAddress=SANCTIONED))["decision"] == "reject"
    assert "HIGH_VALUE_TRANSFER" in circle("transfer", transfer(amounts=["5000"]))["flags"]  # default ceiling 1000


def test_unlimited_approve_via_contract_execution_is_held():
    body = {"walletId": WALLET_ID, "blockchain": "ARC-TESTNET", "contractAddress": USDC_ARC,
            "abiFunctionSignature": "approve(address,uint256)", "abiParameters": [OTHER, str(2**256 - 1)]}
    out = circle("contractExecution", body)
    assert out["decision"] == "hold" and "UNLIMITED_APPROVAL" in out["flags"]


def test_sign_message_is_held():
    assert circle("signMessage", {"walletId": WALLET_ID, "message": "login"})["flags"] == ["UNSUPPORTED_OPERATION"]


def test_wallet_must_match_sender():
    assert circle("transfer", transfer(walletAddress=OTHER))["flags"] == ["WALLET_MISMATCH"]


def test_configured_wallets_restrict_which_wallet_can_be_used(monkeypatch):
    monkeypatch.setenv("SRA_CIRCLE_WALLETS", f"{WALLET_ID}={ME}")
    assert circle("transfer", transfer())["decision"] == "approve"
    assert circle("transfer", transfer(walletId="d5e2eb83-222f-4e63-ceac-3f85b3e914e6"))["flags"] == ["UNKNOWN_WALLET"]
    # the agent cannot claim a configured wallet is at another address
    assert circle("transfer", transfer(), sender=OTHER)["flags"] == ["WALLET_MISMATCH"]


def test_malformed_wallet_config_is_a_configuration_error(monkeypatch):
    monkeypatch.setenv("SRA_CIRCLE_WALLETS", "not-a-pair")
    out = circle("transfer", transfer())
    assert out["decision"] == "reject" and out["flags"] == ["configuration_error"]


def test_token_ids_come_from_config(monkeypatch):
    token = "7adb2b7d-c9cd-5164-b2d4-b73b088274dc"
    body = transfer(tokenAddress=None, blockchain=None, tokenId=token)
    body = {k: v for k, v in body.items() if v is not None}
    assert circle("transfer", body, chain_id=5042002)["flags"] == ["UNSUPPORTED_ASSET"]
    monkeypatch.setenv("SRA_CIRCLE_USDC_TOKEN_IDS", token)
    assert circle("transfer", body, chain_id=5042002)["decision"] == "approve"


def test_known_recipients_from_config(monkeypatch):
    monkeypatch.setenv("SRA_KNOWN_RECIPIENTS", OTHER)
    assert "NEW_COUNTERPARTY" in circle("transfer", transfer())["flags"]


def test_garbage_never_approves():
    for body in ("not json", {}, {"walletId": WALLET_ID}):
        assert circle("transfer", body)["decision"] != "approve"
