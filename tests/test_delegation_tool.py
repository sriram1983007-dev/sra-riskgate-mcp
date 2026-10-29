"""0.9.1: check_delegation holds every EIP-7702 authorization."""
import json

import pytest

from test_server import call

DELEGATE = "0x" + "d" * 40


@pytest.mark.parametrize("auth", [{"address": DELEGATE, "chainId": 0, "nonce": 0},
                                  {"contractAddress": DELEGATE, "chainId": 8453, "nonce": 3},
                                  json.dumps({"address": DELEGATE, "chainId": 0}), None, "not json"])
def test_always_held(auth):
    out = call("check_delegation", {"authorization": auth} if auth is not None else {})
    assert out["decision"] == "hold" and out["flags"] == ["CODE_DELEGATION"]


def test_explains_target_and_scope():
    out = call("check_delegation", {"authorization": {"address": DELEGATE, "chainId": 0, "nonce": 0}})
    assert DELEGATE in out["explanation"].lower() and "every chain" in out["explanation"]
