from datetime import date, timedelta

import pytest

import sra_riskgate.client as sdk_client
from sra_riskgate.sanctions import bundled_as_of

_COUNTERPARTY_ENV = ("SRA_KNOWN_RECIPIENTS", "SRA_KNOWN_RECIPIENTS_FILE",
                     "SRA_BLOCKED_ADDRESSES", "SRA_BLOCKED_ADDRESSES_FILE",
                     # 0.16.0: screening providers, so a developer's own keys never reach the tests
                     "SRA_CHAINALYSIS_API_KEY", "SRA_TRM_API_KEY", "SRA_TRM_KEYLESS", "SRA_RANGE_API_KEY",
                     "SRA_WEBACY_API_KEY", "SRA_WEBACY_HIGH_RISK_SCORE", "SRA_ELLIPTIC_API_KEY",
                     "SRA_ELLIPTIC_API_SECRET", "SRA_ELLIPTIC_HIGH_RISK_SCORE", "SRA_ELLIPTIC_SEVERE_RISK_SCORE",
                     "SRA_ELLIPTIC_UNSEEN_IS_CLEAN", "SRA_SCREENING_HOLD_AT", "SRA_SCREENING_REJECT_AT",
                     "SRA_SCREENING_TIMEOUT")


@pytest.fixture(autouse=True)
def stable_environment(monkeypatch):
    """Pin "today" just after the bundled sanctions snapshot, so the SDK's SANCTIONS_LIST_STALE flag does
    not appear in results as the calendar moves on, and clear any counterparty lists from the
    developer's own environment."""
    monkeypatch.setattr(sdk_client, "_today", lambda: date.fromisoformat(bundled_as_of()) + timedelta(days=1))
    for name in _COUNTERPARTY_ENV:
        monkeypatch.delenv(name, raising=False)
