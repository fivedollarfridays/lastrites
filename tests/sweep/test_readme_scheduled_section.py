"""README must document the env-contract and install-proof steps.

A doc gap here is not cosmetic: an operator who never reads the contract
can wire a crontab line that silently never stamps `invoked_by=scheduler`,
defeating strict provenance before it protects anything.
"""

from __future__ import annotations

from pathlib import Path


def _readme() -> str:
    return (Path(__file__).resolve().parents[2] / "README.md").read_text()


def test_readme_has_a_running_it_scheduled_section():
    assert "## Running it scheduled" in _readme()


def test_readme_documents_the_env_contract_variable():
    from lastrites.sweep.contract import ENV_VAR

    assert ENV_VAR in _readme()


def test_readme_documents_the_install_proof_step():
    text = _readme()
    assert "env -i" in text
    assert "install" in text.lower()
