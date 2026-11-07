"""0.11.0: verify_settlement, verify_gateway_balances, and maxTimeoutSeconds in check_x402_payment."""
import pytest

from sra_riskgate.chains import GATEWAY_WALLET_ADDRESSES, USDC_ADDRESSES
from sra_riskgate.settlement import AUTHORIZATION_USED_TOPIC, TRANSFER_TOPIC

from test_server import call

AGENT = "0xe542BC293D03D33445189f7E85365Be3Dc087384"
PAYEE = "0x870bcb94683cc25494cd35dd21cFC6E155f17DDc"
USDC = USDC_ADDRESSES[84532]
NONCE = "0x" + "ab" * 32


def word(a):
    return "0x" + a.lower()[2:].rjust(64, "0")


def receipt(micro=10_000, to=PAYEE, status="0x1", nonce=None):
    logs = [{"address": USDC, "topics": [TRANSFER_TOPIC, word(AGENT), word(to)], "data": "0x" + format(micro, "064x")}]
    if nonce:
        logs.insert(0, {"address": USDC, "topics": [AUTHORIZATION_USED_TOPIC, word(AGENT), nonce], "data": "0x"})
    return {"status": status, "blockNumber": hex(53339258), "logs": logs}


def settle(rc, **kw):
    args = {"receipt": rc, "chain_id": 84532, "payer": AGENT, "payee": PAYEE, "amount_usdc": "0.01", **kw}
    return call("verify_settlement", args)


def test_settlement_verified():
    r = settle(receipt())
    assert r["verified"] is True and r["block_number"] == 53339258 and r["source"] == "rules"


def test_settlement_as_json_string():
    import json
    assert settle(json.dumps(receipt()))["verified"] is True


@pytest.mark.parametrize("rc,flag", [(receipt(micro=9_999), "SETTLEMENT_AMOUNT_MISMATCH"),
                                     (receipt(to="0x" + "7e57" * 10), "SETTLEMENT_PAYEE_MISMATCH"),
                                     (receipt(status="0x0"), "SETTLEMENT_FAILED"),
                                     ("not json", "INVALID_RECEIPT")])
def test_settlement_not_verified(rc, flag):
    r = settle(rc)
    assert r["verified"] is False and r["flags"] == [flag]


def test_settlement_nonce():
    assert settle(receipt(nonce=NONCE), authorization_nonce=NONCE)["verified"] is True
    assert settle(receipt(), authorization_nonce=NONCE)["flags"] == ["AUTHORIZATION_NOT_USED"]


def test_gateway_balances():
    ok = call("verify_gateway_balances", {"amount_usdc": "0.01", "payer_before": "0.090000",
                                          "payer_after": "0.080000", "payee_before": "0.010000",
                                          "payee_after": "0.020000"})
    assert ok["verified"] is True
    pending = call("verify_gateway_balances", {"amount_usdc": "0.01", "payer_before": "0.09", "payer_after": "0.08",
                                               "payee_before": "0.01", "payee_after": "0.01"})
    assert pending["flags"] == ["GATEWAY_PAYEE_NOT_CREDITED"]


def x402(**kw):
    args = {"network": "eip155:84532", "asset": USDC, "amount": "10000", "pay_to": PAYEE, "payer": AGENT, **kw}
    return call("check_x402_payment", args)


def test_x402_one_hour_timeout_passes():
    assert x402(max_timeout_seconds=3600)["decision"] == "approve"
    assert x402()["decision"] == "approve"  # optional, as before


def test_x402_long_timeout_is_held():
    r = x402(max_timeout_seconds=30 * 86400)
    assert r["decision"] == "hold" and r["flags"] == ["LONG_TIMEOUT_REQUESTED"]


def test_x402_gateway_timeout_passes_only_for_circles_contract():
    good = {"name": "GatewayWalletBatched", "version": "1", "verifyingContract": GATEWAY_WALLET_ADDRESSES[84532]}
    assert x402(max_timeout_seconds=604900, extra=good)["decision"] == "approve"
    fake = {**good, "verifyingContract": "0x" + "77" * 20}
    assert x402(max_timeout_seconds=604900, extra=fake)["flags"] == ["UNSUPPORTED_ASSET"]


# 0.12.0: other stablecoins (Audit #13 Finding 2) and standing allowances
USDG_RH = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168"
LENDER = "0x281210097f0de7a8fb6f87310af0f089c9c8de21"


def usdg_receipt(units, token=USDG_RH):
    return {"status": "0x1", "blockNumber": hex(106262957),
            "logs": [{"address": token, "topics": [TRANSFER_TOPIC, word(AGENT), word(LENDER)],
                      "data": "0x" + format(units, "064x")}]}


def test_usdg_settlement_by_name():
    r = call("verify_settlement", {"receipt": usdg_receipt(25_075_000), "chain_id": 4663, "payer": AGENT,
                                   "payee": LENDER, "amount_usdc": "25.075", "token": "USDG"})
    assert r["verified"] is True and "25.075 USDG" in r["explanation"]


def test_token_by_address_with_decimals():
    other = "0x" + "12" * 20
    r = call("verify_settlement", {"receipt": usdg_receipt(10 * 10**18, token=other), "chain_id": 4663,
                                   "payer": AGENT, "payee": LENDER, "amount_usdc": "10", "token": other,
                                   "decimals": 18, "symbol": "TKN"})
    assert r["verified"] is True and "exactly 10 TKN" in r["explanation"]


def test_named_token_on_unlisted_chain_is_refused():
    r = call("verify_settlement", {"receipt": usdg_receipt(25_075_000), "chain_id": 8453, "payer": AGENT,
                                   "payee": LENDER, "amount_usdc": "25.075", "token": "USDT"})
    assert r["verified"] is False and r["flags"] == ["CONFIGURATION_ERROR"]


def test_check_allowances_tool(monkeypatch):
    monkeypatch.setenv("SRA_EXPECTED_SPENDERS", LENDER)
    monkeypatch.setenv("SRA_MAX_ALLOWANCE", "50")
    ok = call("check_allowances", {"owner": AGENT, "allowances": {LENDER: "0"}, "token": "USDG", "chain_id": 4663})
    assert ok["decision"] == "approve"
    big = call("check_allowances", {"owner": AGENT, "allowances": {LENDER: str(2**256 - 1)}})
    assert big["decision"] == "hold" and big["flags"] == ["UNLIMITED_ALLOWANCE"]
    stranger = call("check_allowances", {"owner": AGENT, "allowances": {"0x" + "77" * 20: "5000000"}})
    assert stranger["flags"] == ["UNKNOWN_SPENDER"]
    over = call("check_allowances", {"owner": AGENT, "allowances": {LENDER: "60000000"}})
    assert over["flags"] == ["ALLOWANCE_ABOVE_LIMIT"]


def test_check_allowances_blocked_spender(monkeypatch):
    bad = "0x" + "66" * 20
    monkeypatch.setenv("SRA_BLOCKED_ADDRESSES", bad)
    r = call("check_allowances", {"owner": AGENT, "allowances": {bad: "1"}})
    assert r["decision"] == "reject" and r["flags"] == ["BLOCKLISTED_SPENDER"]
