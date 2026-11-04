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
