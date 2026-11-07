"""0.13.0: USDT, USDB and USDG in the checks before signing, enabled on the server with SRA_ALLOWED_TOKENS."""
import pytest

from sra_riskgate.chains import STABLECOINS, USDC_ADDRESSES

from test_server import call

ME, YOU, OTHER = "0x" + "a" * 40, "0x" + "b" * 40, "0x" + "c" * 40
USDT = STABLECOINS["USDT"][1][0]
USDG_RH = STABLECOINS["USDG"][4663][0]
USDB_BASE = STABLECOINS["USDB"][8453][0]
NOW_FAR = 4_000_000_000


def transfer(to=YOU, atomic=20_000_000):
    return "0xa9059cbb" + to.lower()[2:].zfill(64) + format(atomic, "064x")


def approve(spender=OTHER, atomic=2**256 - 1):
    return "0x095ea7b3" + spender.lower()[2:].zfill(64) + format(atomic, "064x")


def rules(**kw):
    args = dict(chain_id=1, sender=ME, recipient=YOU, amount_usdc=20, peg_deviation_pct=0.0)
    args.update(kw)
    return call("check_payment_rules", args)


def tx(chain_id, to, data):
    return call("check_transaction", dict(chain_id=chain_id, sender=ME, to=to, data=data, peg_deviation_pct=0.0))


def _w(x: int) -> str:
    return format(x, "064x")


def _execute_batch(calls):
    """ABI-encode executeBatch((address,uint256,bytes)[]) arguments, value 0 for each call."""
    tuples = []
    for to, data in calls:
        b = data[2:]
        padded = b + "0" * (-len(b) % 64)
        tuples.append(to.lower()[2:].zfill(64) + _w(0) + _w(0x60) + _w(len(b) // 2) + padded)
    offsets, pos = [], 32 * len(tuples)
    for t in tuples:
        offsets.append(_w(pos))
        pos += len(t) // 2
    return _w(0x20) + _w(len(tuples)) + "".join(offsets) + "".join(tuples)


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "USDC, USDT, USDB, USDG")


# ------------------------------------------------------------------ check_payment_rules
def test_usdc_default_unchanged():
    assert rules()["decision"] == "approve"
    assert rules(token="usdc", chain_id=8453)["decision"] == "approve"


def test_other_tokens_held_until_enabled():
    out = rules(token="USDT")
    assert out["decision"] == "hold" and out["flags"] == ["unsupported_asset"]
    assert "SRA_ALLOWED_TOKENS" in out["explanation"]


@pytest.mark.parametrize("token,chain", [("USDT", 1), ("USDB", 1), ("USDB", 8453), ("USDG", 1), ("USDG", 4663)])
def test_enabled_tokens_are_checked(enabled, token, chain):
    assert rules(token=token, chain_id=chain)["decision"] == "approve"


def test_enabled_token_on_wrong_chain_is_held(enabled):
    out = rules(token="USDT", chain_id=8453)
    assert out["flags"] == ["unsupported_chain"] and "USDT" in out["explanation"]


def test_unknown_token_is_held(enabled):
    assert rules(token="DAI")["flags"] == ["unsupported_asset"]


def test_limit_applies_in_the_token_paid(enabled, monkeypatch):
    monkeypatch.setenv("SRA_MAX_AMOUNT", "10")
    out = rules(token="USDG", chain_id=4663, amount_usdc=25.075)
    assert out["decision"] == "hold" and "HIGH_VALUE_TRANSFER" in out["flags"]


def test_bad_setting_is_a_configuration_error(monkeypatch):
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "USDC,DOGE")
    for out in (rules(), tx(1, USDC_ADDRESSES[1], transfer())):
        assert out["decision"] == "reject" and out["flags"] == ["configuration_error"]


def test_blank_setting_means_usdc_only(monkeypatch):
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "  ")
    assert rules()["decision"] == "approve" and rules(token="USDT")["decision"] == "hold"


# ------------------------------------------------------------------ check_transaction
def test_usdt_transfer_held_then_approved(monkeypatch):
    out = tx(1, USDT, transfer())
    assert out["flags"] == ["UNSUPPORTED_ASSET"] and out["decoded"] == {
        "recipient": YOU, "token": "USDT", "amount": "20"}
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "USDC,USDT")
    assert tx(1, USDT, transfer())["decision"] == "approve"


def test_usdg_on_robinhood_chain(enabled):
    out = tx(4663, USDG_RH, transfer(atomic=25_075_000))
    assert out["decision"] == "approve" and out["decoded"]["amount"] == "25.075"


def test_approval_held_for_every_token(enabled):
    for chain, token in ((1, USDT), (8453, USDB_BASE), (4663, USDG_RH)):
        assert tx(chain, token, approve())["flags"] == ["TOKEN_APPROVAL", "UNLIMITED_APPROVAL"]


# ------------------------------------------------------------------ check_x402_authorization
def test_eip3009_for_usdg_is_held(enabled):
    td = {"primaryType": "TransferWithAuthorization",
          "domain": {"name": "Global Dollar", "version": "1", "chainId": 4663, "verifyingContract": USDG_RH},
          "message": {"from": ME, "to": YOU, "value": "1000000", "validAfter": "0",
                      "validBefore": str(NOW_FAR), "nonce": "0x" + "ab" * 32}}
    out = call("check_x402_authorization", dict(typed_data=td, sender=ME))
    assert out["decision"] == "hold" and "UNSUPPORTED_SIGNATURE" in out["flags"]


# ------------------------------------------------------------------ check_circle_wallets_request
def test_circle_transfer_of_usdt(monkeypatch):
    body = {"walletId": "w1", "blockchain": "ETH", "tokenAddress": USDT, "destinationAddress": YOU,
            "amounts": ["2.5"]}
    args = dict(operation="transfer", request=body, sender=ME, peg_deviation_pct=0.0)
    assert call("check_circle_wallets_request", args)["flags"] == ["UNSUPPORTED_ASSET"]
    monkeypatch.setenv("SRA_ALLOWED_TOKENS", "USDC USDT")
    assert call("check_circle_wallets_request", args)["decision"] == "approve"


# ------------------------------------------------------------------ check_user_operation
def test_user_operation_split_across_tokens_is_summed(enabled, monkeypatch):
    monkeypatch.setenv("SRA_MAX_AMOUNT", "1000")
    calls = [(USDC_ADDRESSES[1], transfer(atomic=600_000_000)), (USDT, transfer(atomic=600_000_000))]
    data = "0x34fcd5be" + _execute_batch(calls)
    op = {"sender": ME, "nonce": "0x0", "callData": data, "callGasLimit": "0x1", "verificationGasLimit": "0x1",
          "preVerificationGas": "0x1", "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1", "signature": "0x"}
    out = call("check_user_operation", dict(user_operation=op, chain_id=1, sender=ME, peg_deviation_pct=0.0))
    assert out["decision"] == "hold" and "BATCH_TOTAL" in out["flags"]
