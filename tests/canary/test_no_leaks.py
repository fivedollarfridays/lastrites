"""Grep-proof: evidence rows carry no response bodies and no credential
values.

Structural checks (the shape can't hold a body/value) plus an end-to-end
run that plants both a secret credential value and a response body
carrying a marker, then greps stdout, stderr, and the store file's raw
bytes for both.
"""

from __future__ import annotations

import dataclasses

from lastrites.canary.engine import run_probe
from lastrites.canary.models import ProbeOutcome
from lastrites.canary.providers import PROVIDERS
from lastrites.canary.transport import ProbeResponse
from lastrites.cli import main
from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore

SECRET = "sk-mock-canary-no-leak-value-7f3a2b91"
BODY_MARKER = "mock-response-body-should-never-be-stored-c4d6e805"
PEPPER = b"\x2a" * 32

_FORBIDDEN_FIELD_NAMES = {
    "body",
    "response_body",
    "value",
    "raw_value",
    "secret",
    "plaintext",
}


# --- structural: the outcome shape cannot hold a body or a value -----------


def test_probe_outcome_has_no_body_or_value_shaped_field():
    field_names = {f.name for f in dataclasses.fields(ProbeOutcome)}
    assert not (field_names & _FORBIDDEN_FIELD_NAMES)


def test_engine_return_value_never_carries_the_response_body():
    spec = PROVIDERS["cloudflare"]
    response = ProbeResponse(
        status=200, body=f'{{"success":true,"leak":"{BODY_MARKER}"}}'.encode()
    )
    outcome = run_probe(spec, SECRET, transport=lambda request, timeout=None: response)

    rendered = repr(outcome) + str(dataclasses.asdict(outcome))
    assert BODY_MARKER not in rendered
    assert SECRET not in rendered


# --- end-to-end: CLI + store, both markers, both surfaces -------------------


def test_end_to_end_cli_and_store_never_carry_the_secret_or_the_body(
    monkeypatch, tmp_path, capsys
):
    pepper_file = tmp_path / "pepper"
    pepper_file.write_bytes(PEPPER)
    value_file = tmp_path / "value"
    value_file.write_text(SECRET)
    db = tmp_path / "graph.sqlite3"

    fp = fingerprint(PEPPER, SECRET)
    store = GraphStore(db)
    store.add_credential(
        fingerprint=fp,
        kind="api-token",
        rotation_class="unknown",
        provider="cloudflare",
    )
    store.close()

    response = ProbeResponse(
        status=200, body=f'{{"success":true,"leak":"{BODY_MARKER}"}}'.encode()
    )
    monkeypatch.setattr(
        "lastrites.canary.transport.send", lambda request, timeout=None: response
    )

    main(
        [
            "canary",
            fp[:12],
            "--provider",
            "cloudflare",
            "--value-file",
            str(value_file),
            "--store",
            str(db),
            "--pepper-file",
            str(pepper_file),
        ]
    )

    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert BODY_MARKER not in captured.out + captured.err

    for candidate in tmp_path.glob("graph.sqlite3*"):
        data = candidate.read_bytes()
        assert SECRET.encode() not in data
        assert BODY_MARKER.encode() not in data
