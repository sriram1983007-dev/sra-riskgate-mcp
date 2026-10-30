"""0.9.2: an already-delegated wallet (eth_getCode = 0xef0100 + delegate) is held by every payment tool."""
import pytest

from sra_riskgate.chains import USDC_ADDRESSES

from test_server import call

ME, PAYEE = "0x" + "a" * 40, "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
DESIGNATOR = "0xef0100" + "d" * 40
TRANSFER = "0xa9059cbb" + PAYEE[2:].zfill(64) + format(1_000_000, "064x")

CALLS = {
    "check_payment_rules": dict(chain_id=8453, sender=ME, recipient=PAYEE, amount_usdc=5, peg_deviation_pct=0.1),
    "check_transaction": dict(chain_id=8453, sender=ME, to=USDC_ADDRESSES[8453], data=TRANSFER, peg_deviation_pct=0.1),
    "check_circle_wallets_request": dict(operation="transfer", sender=ME, peg_deviation_pct=0.1, request={
        "walletAddress": ME, "blockchain": "BASE", "tokenAddress": USDC_ADDRESSES[8453],
        "destinationAddress": PAYEE, "amounts": ["1"]}),
}


@pytest.mark.parametrize("tool", sorted(CALLS))
def test_delegated_wallet_is_held(tool):
    assert call(tool, CALLS[tool])["decision"] == "approve"
    out = call(tool, {**CALLS[tool], "account_code": DESIGNATOR})
    assert out["decision"] == "hold" and out["flags"] == ["ACCOUNT_DELEGATED"]


@pytest.mark.parametrize("tool", sorted(CALLS))
def test_plain_account_passes(tool):
    assert call(tool, {**CALLS[tool], "account_code": "0x"})["decision"] == "approve"


def test_expected_delegate_comes_from_config(monkeypatch):
    args = {**CALLS["check_payment_rules"], "account_code": DESIGNATOR}
    monkeypatch.setenv("SRA_EXPECTED_DELEGATES", "0x" + "d" * 40)
    assert call("check_payment_rules", args)["decision"] == "approve"
    monkeypatch.setenv("SRA_EXPECTED_DELEGATES", "not-an-address")
    assert call("check_payment_rules", args)["flags"] == ["configuration_error"]
