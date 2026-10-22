from datetime import date, timedelta

import pytest

import sra_riskgate.client as sdk_client
from sra_riskgate.sanctions import bundled_as_of

_COUNTERPARTY_ENV = ("SRA_KNOWN_RECIPIENTS", "SRA_KNOWN_RECIPIENTS_FILE",
                     "SRA_BLOCKED_ADDRESSES", "SRA_BLOCKED_ADDRESSES_FILE")


@pytest.fixture(autouse=True)
def stable_environment(monkeypatch):
    """Pin "today" just after the bundled sanctions snapshot, so the SDK's SANCTIONS_LIST_STALE flag does
    not appear in results as the calendar moves on, and clear any counterparty lists from the
    developer's own environment."""
    monkeypatch.setattr(sdk_client, "_today", lambda: date.fromisoformat(bundled_as_of()) + timedelta(days=1))
    for name in _COUNTERPARTY_ENV:
        monkeypatch.delenv(name, raising=False)
