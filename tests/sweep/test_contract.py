"""The environment contract: presence, not value, decides invoked_by.

A cron line only has to export the var -- it does not have to agree with
us on a sentinel value -- so presence alone is the contract.
"""

from __future__ import annotations

from lastrites.sweep.contract import ENV_VAR, INTERACTIVE, SCHEDULER, invoked_by


def test_absent_env_var_is_interactive(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert invoked_by() == INTERACTIVE


def test_present_env_var_is_scheduler(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "1")
    assert invoked_by() == SCHEDULER


def test_present_but_empty_env_var_is_still_scheduler(monkeypatch):
    """Presence is the contract, not the value -- an empty export still counts."""
    monkeypatch.setenv(ENV_VAR, "")
    assert invoked_by() == SCHEDULER
