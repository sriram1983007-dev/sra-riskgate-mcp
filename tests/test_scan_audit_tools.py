"""0.20.0: scan_wallet_for_poisoning (sra-riskgate 1.14.0) and receipt_audit_report (sra-riskgate 1.12.0)."""
import json
import random

import pytest

from sra_riskgate.scan import TRANSFER_TOPIC, ScanError

from test_server import call

USDC_ETH = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WALLET = "0x" + "a1" * 20
PAYEE = "0x2ffb88f73980bc6069c598487396e1e472deb7ee"
KEY_HEX = "11" * 32
SECRET_URL = "https://eth-mainnet.example/v2/SECRET-API-KEY"


def lookalike(real, prefix, suffix):
    rng, h = random.Random(1), real[2:]
    mid = "".join(rng.choice([c for c in "0123456789abcdef" if c != h[i]]) for i in range(prefix, 40 - suffix))
    return "0x" + h[:prefix] + mid + h[40 - suffix:]


def topic(a):
    return "0x" + "0" * 24 + a[2:]


class FakeRPC:
    def __init__(self, fail=None):
        self.logs, self.fail, self.n = [], fail, 0

    def transfer(self, frm, to, value, block):
        self.n += 1
        self.logs.append({"address": USDC_ETH, "blockNumber": hex(block), "transactionHash": f"0x{self.n:064x}",
                          "topics": [TRANSFER_TOPIC, topic(frm), topic(to)], "data": hex(value)})

    def __call__(self, method, params):
        if self.fail:
            raise ScanError(self.fail)
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_blockNumber":
            return hex(1_000_000)
        f = params[0]
        lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
        return [lg for lg in self.logs if lo <= int(lg["blockNumber"], 16) <= hi
                and all(w is None or lg["topics"][i] == w for i, w in enumerate(f["topics"]))]


@pytest.fixture
def rpc(monkeypatch):
    fake = FakeRPC()
    seen = {}

    def factory(url, timeout=30.0):
        seen["url"] = url
        return fake
    monkeypatch.setattr("sra_riskgate.scan._http_rpc", factory)
    monkeypatch.setenv("SRA_RPC_URL", SECRET_URL)
    fake.seen = seen
    return fake


# ---------------------------------------------------------------- scan_wallet_for_poisoning

def test_scan_finds_a_planted_lookalike(rpc):
    fake = lookalike(PAYEE, 4, 4)
    rpc.transfer(WALLET, PAYEE, 250_000_000, 990_000)
    rpc.transfer(WALLET, fake, 0, 990_100)
    out = call("scan_wallet_for_poisoning", {"wallet": WALLET})
    assert out["ok"] and out["found"] and out["blocked_addresses"] == [fake]
    assert out["findings"][0]["imitates"] == PAYEE and out["findings"][0]["kinds"] == ["zero_value_transfer"]
    assert "SRA_BLOCKED_ADDRESSES" in out["next_step"] and "payee_addresses" not in out
    assert rpc.seen["url"] == SECRET_URL


def test_scan_uses_strict_rule_and_server_known_payees(rpc, monkeypatch):
    fake = lookalike(PAYEE, 3, 3)
    rpc.transfer(fake, WALLET, 1, 990_000)                     # dust only: no payment made from this wallet
    assert call("scan_wallet_for_poisoning", {"wallet": WALLET})["found"] is False
    monkeypatch.setenv("SRA_KNOWN_RECIPIENTS", PAYEE)
    out = call("scan_wallet_for_poisoning", {"wallet": WALLET})
    assert out["blocked_addresses"] == [fake] and out["findings"][0]["kinds"] == ["dust_received"]


def test_clean_and_incomplete_are_told_apart(rpc, monkeypatch):
    rpc.transfer(WALLET, PAYEE, 1, 990_000)
    out = call("scan_wallet_for_poisoning", {"wallet": WALLET})
    assert out["found"] is False and out["complete"] and out["next_step"].startswith("No look-alikes")
    monkeypatch.setattr("sra_riskgate_mcp.server._SCAN_MAX_REQUESTS", 1)
    out = call("scan_wallet_for_poisoning", {"wallet": WALLET})
    assert out["complete"] is False and "not a clean result" in out["next_step"]


def test_scan_needs_a_server_rpc_url(monkeypatch):
    monkeypatch.delenv("SRA_RPC_URL", raising=False)
    out = call("scan_wallet_for_poisoning", {"wallet": WALLET})
    assert out["ok"] is False and "SRA_RPC_URL" in out["reason"]


def test_scan_never_echoes_the_rpc_url(monkeypatch):
    monkeypatch.setenv("SRA_RPC_URL", SECRET_URL)
    monkeypatch.setattr("sra_riskgate.scan._http_rpc",
                        lambda url, timeout=30.0: FakeRPC(fail=f"RPC unreachable: {url} refused"))
    out = call("scan_wallet_for_poisoning", {"wallet": WALLET})
    assert out["ok"] is False and "SECRET-API-KEY" not in json.dumps(out) and "<SRA_RPC_URL>" in out["reason"]


def test_scan_bad_inputs(rpc, monkeypatch):
    assert call("scan_wallet_for_poisoning", {"wallet": "0x123"})["ok"] is False
    assert call("scan_wallet_for_poisoning", {"wallet": WALLET, "blocks": 0})["ok"] is False
    assert call("scan_wallet_for_poisoning", {"wallet": WALLET, "blocks": 2_000_000})["ok"] is False
    monkeypatch.setenv("SRA_KNOWN_RECIPIENTS", "not-an-address")
    assert call("scan_wallet_for_poisoning", {"wallet": WALLET})["ok"] is False
    monkeypatch.setenv("SRA_KNOWN_RECIPIENTS_FILE", "/nonexistent/file")
    assert call("scan_wallet_for_poisoning", {"wallet": WALLET})["ok"] is False


def test_scan_takes_no_url_argument():
    import asyncio
    from sra_riskgate_mcp import server
    tool = {t.name: t for t in asyncio.run(server.mcp.list_tools())}["scan_wallet_for_poisoning"]
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema")
    assert set(schema["properties"]) == {"wallet", "blocks"}


# ---------------------------------------------------------------- receipt_audit_report

def _receipts(monkeypatch, tmp_path, n=3):
    monkeypatch.setenv("SRA_RECEIPT_KEY", KEY_HEX)
    chain = tmp_path / "chain.jsonl"
    monkeypatch.setenv("SRA_RECEIPT_CHAIN_FILE", str(chain))
    for i in range(n):
        call("check_payment_rules", {"chain_id": 8453, "sender": WALLET, "recipient": PAYEE, "amount_usdc": 10 + i})
    return chain


def test_audit_report_from_the_servers_own_chain(monkeypatch, tmp_path):
    _receipts(monkeypatch, tmp_path)
    out = call("receipt_audit_report", {"include_markdown": True})
    assert out["ok"] and out["report"]["receipts"] == 3 and out["report"]["verified"] == 3
    assert out["report"]["chain"]["intact"] is True and out["markdown"].startswith("#")


def test_audit_report_excludes_edited_receipts(monkeypatch, tmp_path):
    chain = _receipts(monkeypatch, tmp_path)
    rows = [json.loads(x) for x in chain.read_text().splitlines()]
    rows[1]["decision"] = "approve" if rows[1]["decision"] != "approve" else "reject"
    out = call("receipt_audit_report", {"receipts": rows})
    assert out["ok"] is False and out["report"]["invalid"] == 1


def test_audit_report_needs_a_key_and_receipts(monkeypatch, tmp_path):
    monkeypatch.delenv("SRA_RECEIPT_KEY", raising=False)
    assert "no SRA_RECEIPT_KEY" in call("receipt_audit_report", {})["reason"]
    monkeypatch.setenv("SRA_RECEIPT_KEY", KEY_HEX)
    monkeypatch.delenv("SRA_RECEIPT_CHAIN_FILE", raising=False)
    assert "SRA_RECEIPT_CHAIN_FILE" in call("receipt_audit_report", {})["reason"]
    monkeypatch.setenv("SRA_RECEIPT_CHAIN_FILE", str(tmp_path / "missing.jsonl"))
    assert call("receipt_audit_report", {})["ok"] is False
    assert call("receipt_audit_report", {"receipts": []})["ok"] is False
