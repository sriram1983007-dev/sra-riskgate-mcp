"""0.16.0: screening providers configured by environment variables, in all six payment tools."""
import base64
import json

import pytest

import sra_riskgate.screening as scr
from sra_riskgate.chains import USDC_ADDRESSES

from test_authorization_tool import typed
from test_server import call

ME, YOU = "0x" + "a" * 40, "0x" + "b" * 40
BAD = "0x" + "d" * 40
SECRET = base64.b64encode(b"test-secret").decode()


class Net:
    """Stands in for the network: answers each provider's documented response shape, and records every call."""

    def __init__(self, bad=(BAD,), down=False):
        self.bad, self.down, self.calls = {a.lower() for a in bad}, down, []

    def get(self, url, headers, timeout):
        self.calls.append(("GET", url))
        if self.down:
            raise TimeoutError()
        hit = any(a in url.lower() for a in self.bad)
        return 200, {"identifications": [{"category": "sanctions", "name": "SDN"}] if hit else []}

    def post(self, url, headers, body, timeout):
        self.calls.append(("POST", url))
        if self.down:
            raise TimeoutError()
        if "elliptic" in url:
            addr = json.loads(body)["subject"]["hash"].lower()
            ents = [{"name": "Listed", "category": "Sanctions", "is_primary_entity": True}] if addr in self.bad else []
            return 200, {"process_status": "complete", "risk_score": None, "error": None, "cluster_entities": ents,
                         "evaluation_detail": {"source": [], "destination": []}}
        addr = body[0]["address"]
        return 200, [{"address": addr, "isSanctioned": addr.lower() in self.bad}]


@pytest.fixture
def net(monkeypatch):
    n = Net()
    monkeypatch.setattr(scr, "_urllib_get", n.get)
    monkeypatch.setattr(scr, "_urllib_post", n.post)
    return n


def rules(recipient=YOU, **kw):
    return call("check_payment_rules", {"chain_id": 8453, "sender": ME, "recipient": recipient, "amount_usdc": 5,
                                        "peg_deviation_pct": 0.0, **kw})


def transfer_data(to, atomic=5_000_000):
    return "0xa9059cbb" + to[2:].lower().rjust(64, "0") + format(atomic, "x").rjust(64, "0")


def test_without_providers_nothing_leaves_the_machine(net):
    assert rules(BAD)["decision"] == "approve" and net.calls == []


@pytest.mark.parametrize("env", [{"SRA_CHAINALYSIS_API_KEY": "k"}, {"SRA_TRM_API_KEY": "k"}, {"SRA_TRM_KEYLESS": "1"},
                                 {"SRA_ELLIPTIC_API_KEY": "k", "SRA_ELLIPTIC_API_SECRET": SECRET}])
def test_each_provider_rejects_a_sanctioned_payee_and_passes_a_clean_one(net, monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    out = rules(BAD)
    assert out["decision"] == "reject" and "PROVIDER_SANCTIONS_MATCH" in out["flags"]
    clean = rules(YOU)
    assert clean["decision"] == "approve"
    assert len(net.calls) == 4  # sender and payee, for each of the two payments


def test_a_provider_with_no_answer_holds(net, monkeypatch):
    monkeypatch.setenv("SRA_CHAINALYSIS_API_KEY", "k")
    net.down = True
    out = rules(YOU)
    assert out["decision"] == "hold" and "SCREENING_UNAVAILABLE" in out["flags"]


def test_local_reject_makes_no_provider_calls(net, monkeypatch):
    monkeypatch.setenv("SRA_CHAINALYSIS_API_KEY", "k")
    assert rules(YOU, amount_usdc=-1)["decision"] == "reject"
    assert net.calls == []


def test_screening_hold_merges_with_a_local_hold(net, monkeypatch):
    monkeypatch.setenv("SRA_CHAINALYSIS_API_KEY", "k")
    net.down = True
    monkeypatch.setenv("SRA_KNOWN_RECIPIENTS", ME)
    out = rules(YOU)
    assert out["decision"] == "hold"
    assert "SCREENING_UNAVAILABLE" in out["flags"] and "NEW_COUNTERPARTY" in out["flags"]


def test_x402_payment(net, monkeypatch):
    monkeypatch.setenv("SRA_TRM_KEYLESS", "1")
    args = dict(network="eip155:8453", asset=USDC_ADDRESSES[8453], amount="5000000", payer=ME, peg_deviation_pct=0.0)
    assert call("check_x402_payment", {**args, "pay_to": BAD})["decision"] == "reject"
    assert call("check_x402_payment", {**args, "pay_to": YOU})["decision"] == "approve"


def test_transaction(net, monkeypatch):
    monkeypatch.setenv("SRA_CHAINALYSIS_API_KEY", "k")
    args = dict(chain_id=8453, sender=ME, to=USDC_ADDRESSES[8453], peg_deviation_pct=0.0)
    out = call("check_transaction", {**args, "data": transfer_data(BAD)})
    assert out["decision"] == "reject" and "PROVIDER_SANCTIONS_MATCH" in out["flags"]
    assert call("check_transaction", {**args, "data": transfer_data(YOU)})["decision"] == "approve"


def test_x402_authorization(net, monkeypatch):
    monkeypatch.setenv("SRA_ELLIPTIC_API_KEY", "k")
    monkeypatch.setenv("SRA_ELLIPTIC_API_SECRET", SECRET)
    out = call("check_x402_authorization", dict(typed_data=typed(to=BAD, value="5000000"), sender=ME,
                                                 peg_deviation_pct=0.0))
    assert out["decision"] == "reject" and "PROVIDER_SANCTIONS_MATCH" in out["flags"]
    ok = call("check_x402_authorization", dict(typed_data=typed(value="5000000"), sender=ME, peg_deviation_pct=0.0))
    assert ok["decision"] == "approve"


def test_circle_wallets_transfer(net, monkeypatch):
    monkeypatch.setenv("SRA_CHAINALYSIS_API_KEY", "k")
    body = {"walletId": "w1", "blockchain": "BASE", "tokenAddress": USDC_ADDRESSES[8453],
            "destinationAddress": BAD, "amounts": ["5"]}
    out = call("check_circle_wallets_request", dict(operation="transfer", request=body, sender=ME, peg_deviation_pct=0.0))
    assert out["decision"] == "reject" and "PROVIDER_SANCTIONS_MATCH" in out["flags"]
    ok = call("check_circle_wallets_request", dict(operation="transfer", request={**body, "destinationAddress": YOU},
                                                   sender=ME, peg_deviation_pct=0.0))
    assert ok["decision"] == "approve"


def test_user_operation_asks_each_provider_once_per_address(net, monkeypatch):
    from test_user_operation_tool import ACCOUNT, ACCOUNTS, CHAIN, PAYEE, op
    monkeypatch.setenv("SRA_CHAINALYSIS_API_KEY", "k")
    out = call("check_user_operation", dict(user_operation=op(ACCOUNTS[0], "single_transfer"), chain_id=CHAIN,
                                            sender=ACCOUNT, peg_deviation_pct=0.0))
    assert out["decision"] == "approve"
    urls = [u for _, u in net.calls]
    assert sorted(urls) == sorted({u for u in urls}) and any(PAYEE.lower() in u.lower() for u in urls)
    net.bad.add(PAYEE.lower())
    out = call("check_user_operation", dict(user_operation=op(ACCOUNTS[0], "single_transfer"), chain_id=CHAIN,
                                            sender=ACCOUNT, peg_deviation_pct=0.0))
    assert out["decision"] == "reject" and "PROVIDER_SANCTIONS_MATCH" in out["flags"]


@pytest.mark.parametrize("env", [
    {"SRA_ELLIPTIC_API_KEY": "k"}, {"SRA_ELLIPTIC_API_SECRET": SECRET},
    {"SRA_ELLIPTIC_API_KEY": "k", "SRA_ELLIPTIC_API_SECRET": "not base64!"},
    {"SRA_ELLIPTIC_API_KEY": "k", "SRA_ELLIPTIC_API_SECRET": SECRET, "SRA_ELLIPTIC_HIGH_RISK_SCORE": "five"},
    {"SRA_ELLIPTIC_API_KEY": "k", "SRA_ELLIPTIC_API_SECRET": SECRET, "SRA_ELLIPTIC_UNSEEN_IS_CLEAN": "maybe"},
    {"SRA_WEBACY_API_KEY": "k", "SRA_WEBACY_HIGH_RISK_SCORE": "-1"},
    {"SRA_CHAINALYSIS_API_KEY": "k", "SRA_SCREENING_HOLD_AT": "loud"},
    {"SRA_CHAINALYSIS_API_KEY": "k", "SRA_SCREENING_HOLD_AT": "severe", "SRA_SCREENING_REJECT_AT": "high"},
    {"SRA_CHAINALYSIS_API_KEY": "k", "SRA_SCREENING_TIMEOUT": "0"},
    {"SRA_TRM_KEYLESS": "on"},
])
def test_a_bad_screening_setting_rejects_every_payment_tool(net, monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    out = rules(YOU)
    assert out["decision"] == "reject" and out["flags"] == ["configuration_error"]
    tx = call("check_transaction", dict(chain_id=8453, sender=ME, to=USDC_ADDRESSES[8453], data=transfer_data(YOU)))
    assert tx["decision"] == "reject" and tx["flags"] == ["configuration_error"]
    assert net.calls == []


def test_thresholds_from_the_environment(net, monkeypatch):
    def webacy(url, headers, timeout):
        net.calls.append(("GET", url))
        return 200, {"high": 0, "medium": 1, "overallRisk": 40, "issues": [], "details": {"address_info": {}}}
    monkeypatch.setattr(scr, "_urllib_get", webacy)
    monkeypatch.setenv("SRA_WEBACY_API_KEY", "k")
    assert rules(YOU)["decision"] == "approve"                   # medium does not hold by default
    monkeypatch.setenv("SRA_SCREENING_HOLD_AT", "medium")
    assert rules(YOU)["decision"] == "hold"
    monkeypatch.delenv("SRA_SCREENING_HOLD_AT")
    monkeypatch.setenv("SRA_WEBACY_HIGH_RISK_SCORE", "30")       # overallRisk 40 now counts as high
    out = rules(YOU)
    assert out["decision"] == "hold" and "PROVIDER_RISK_HIGH" in out["flags"]


def test_payment_tools_are_open_world_only_when_screening_is_configured(monkeypatch):
    import importlib

    import sra_riskgate_mcp.server as server
    from test_counterparty import _annotations
    import asyncio
    payment = {"check_payment_rules", "check_x402_payment", "check_transaction", "check_x402_authorization",
               "check_circle_wallets_request", "check_user_operation"}
    try:
        monkeypatch.setenv("SRA_RANGE_API_KEY", "k")
        importlib.reload(server)
        tools = {t.name: _annotations(t) for t in asyncio.run(server.mcp.list_tools())}
        for name, a in tools.items():
            assert a["openWorldHint"] is (name in payment or name == "check_payment_with_model"), name
            assert a["readOnlyHint"] is True and a["destructiveHint"] is False
    finally:
        monkeypatch.delenv("SRA_RANGE_API_KEY")
        importlib.reload(server)
