"""0.15.0: check_dispute_verdict recomputes the dispute window and escalates denials that rest on a false claim."""
import json

import pytest

from test_server import call

DAY = 86400
PAID = 1_790_000_000
POLICY = {"dispute_window_days": 30, "merchant_response_days": 7}


def dispute(days_after, fmt="sdk"):
    payment, claim = {"paid_at": PAID, "amount_usdc": "25"}, {"filed_at": PAID + int(days_after * DAY), "reason": "x"}
    if fmt == "sdk":
        return {"policy": POLICY, "payload": {"payment": payment, "claim": claim}}
    return {"context": {"now_unix": PAID + 40 * DAY, "policy": POLICY}, "case": {"payment": payment, "claim": claim}}


DISMISS = {"outcome": "dismiss", "mechanism": "none", "settlement_state": "final", "refund_amount_usdc": "0",
           "refund_destination": None, "idempotency_key": None, "flags": ["outside_dispute_window"],
           "explanation": "Filed outside the 30-day window.", "required_actions": []}


def check(d, v):
    return call("check_dispute_verdict", dict(dispute=d, verdict=v))


@pytest.mark.parametrize("fmt", ["sdk", "prompt"])
def test_false_window_claim_is_escalated_never_refunded(fmt):
    out = check(dispute(12.5, fmt), DISMISS)
    assert out["outcome"] == "escalate_to_human" and out["refund_amount_usdc"] == "0"
    assert "outside_dispute_window" not in out["flags"] and "dispute_window_claim_contradicted" in out["flags"]
    assert out["dispute_window"] == {"days_since_payment": 12.5, "window_days": 30.0, "within_window": True}
    assert out["source"] == "rules"


def test_true_window_claim_is_kept():
    out = check(dispute(45), DISMISS)
    assert out["outcome"] == "dismiss" and out["dispute_window"]["within_window"] is False


def test_other_outcomes_are_not_changed_into_refunds():
    refund = {**DISMISS, "outcome": "voluntary_refund", "flags": ["merchant_accepted"]}
    assert check(dispute(5), refund)["outcome"] == "voluntary_refund"
    deny = {**DISMISS, "outcome": "deny", "flags": ["evidence_favours_merchant"]}
    assert check(dispute(5), deny)["outcome"] == "deny"  # no window claim: left alone


def test_raw_model_reply_and_json_strings():
    raw = "```json\n" + json.dumps(DISMISS) + "\n```"
    assert check(json.dumps(dispute(3)), raw)["outcome"] == "escalate_to_human"


def test_window_not_computable_is_flagged_not_guessed():
    d = dispute(3); d["payload"]["claim"]["filed_at"] = None
    out = check(d, DISMISS)
    assert out["outcome"] == "dismiss" and "dispute_window_not_checked" in out["flags"]
    early = dispute(-1)  # claim filed before the payment: no window
    assert "dispute_window_not_checked" in check(early, DISMISS)["flags"]


@pytest.mark.parametrize("verdict", ["not json at all", "", "outcome: refund please"])
def test_unreadable_verdict_escalates(verdict):
    out = check(dispute(3), verdict)
    assert out["outcome"] == "escalate_to_human" and out["refund_amount_usdc"] == "0"
    assert out["flags"] == ["verdict_unreadable"]


def test_unreadable_dispute_never_refunds():
    out = check("{not json", DISMISS)
    assert out["outcome"] == "dismiss" and "dispute_window_not_checked" in out["flags"]


@pytest.mark.parametrize("args", [dict(dispute=7, verdict=DISMISS), dict(dispute=dispute(3), verdict=42),
                                  dict(dispute=dispute(3), verdict="[1, 2]")])
def test_wrong_types_never_refund(args):
    # The schema rejects them (the error class differs between mcp 1.x and 2.x), or the tool escalates.
    try:
        out = call("check_dispute_verdict", args)
    except Exception:
        return
    assert out["outcome"] in ("escalate_to_human", "dismiss") and out.get("refund_amount_usdc", "0") == "0"
