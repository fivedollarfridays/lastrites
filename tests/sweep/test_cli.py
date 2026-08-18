"""`lastrites sweep` -- the operator-facing surface.

Every test that needs a network call monkeypatches
`lastrites.canary.transport.send`, same discipline as the canary CLI
tests: no real socket, ever.
"""

from __future__ import annotations

import json

import pytest

from lastrites.canary.transport import ProbeResponse
from lastrites.cli import main
from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore
from lastrites.sweep.cli import EXIT_SWEEP_FAILED, EXIT_SWEEP_OK
from lastrites.sweep.contract import ENV_VAR
from lastrites.sweep.heartbeat import read_heartbeat

PEPPER = b"\x77" * 32
SECRET = "mock-cf-token-for-sweep-cli-test"


@pytest.fixture
def pepper_file(tmp_path):
    path = tmp_path / "pepper"
    path.write_bytes(PEPPER)
    return path


def _base_argv(tmp_path, **overrides):
    argv = {
        "store": str(tmp_path / "graph.sqlite3"),
        "heartbeat-file": str(tmp_path / "heartbeat.json"),
    }
    argv.update(overrides)
    out = ["sweep"]
    for key, value in argv.items():
        out.extend([f"--{key}", value])
    return out


def run(argv, pepper_file, capsys):
    code = main([*argv, "--pepper-file", str(pepper_file)])
    return code, capsys.readouterr()


# --- help --------------------------------------------------------------


def test_help_exits_clean(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["sweep", "--help"])
    assert exc.value.code == 0
    assert "sweep" in capsys.readouterr().out


# --- completion / heartbeat ---------------------------------------------


def test_completed_sweep_exits_ok_and_writes_heartbeat(tmp_path, pepper_file, capsys):
    argv = _base_argv(tmp_path)
    code, captured = run(argv, pepper_file, capsys)

    assert code == EXIT_SWEEP_OK
    heartbeat = read_heartbeat(tmp_path / "heartbeat.json")
    assert heartbeat.invoked_by == "interactive"


def test_scheduled_invocation_stamps_scheduler(
    tmp_path, pepper_file, capsys, monkeypatch
):
    monkeypatch.setenv(ENV_VAR, "1")
    argv = _base_argv(tmp_path)
    run(argv, pepper_file, capsys)

    heartbeat = read_heartbeat(tmp_path / "heartbeat.json")
    assert heartbeat.invoked_by == "scheduler"


def test_hand_run_without_env_var_stamps_interactive(
    tmp_path, pepper_file, capsys, monkeypatch
):
    monkeypatch.delenv(ENV_VAR, raising=False)
    argv = _base_argv(tmp_path)
    run(argv, pepper_file, capsys)

    heartbeat = read_heartbeat(tmp_path / "heartbeat.json")
    assert heartbeat.invoked_by == "interactive"


def test_sweep_that_fails_exits_nonzero_and_writes_no_heartbeat(
    tmp_path, pepper_file, capsys
):
    argv = _base_argv(
        tmp_path, **{"credentials-config": str(tmp_path / "does-not-exist.json")}
    )
    code, captured = run(argv, pepper_file, capsys)

    assert code == EXIT_SWEEP_FAILED
    assert not (tmp_path / "heartbeat.json").exists()
    assert "ERROR" in captured.err


# --- canarying registered credentials ------------------------------------


def test_registered_credential_is_canaried_and_recorded(
    tmp_path, pepper_file, capsys, monkeypatch
):
    fp = fingerprint(PEPPER, SECRET)
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(
        fp, kind="api-token", rotation_class="unknown", provider="cloudflare"
    )
    store.close()

    creds_config = tmp_path / "credentials.json"
    creds_config.write_text(
        json.dumps(
            [
                {
                    "fingerprint_prefix": fp[:12],
                    "provider": "cloudflare",
                    "value_env": "SWEEP_CLI_VALUE",
                }
            ]
        )
    )
    monkeypatch.setenv("SWEEP_CLI_VALUE", SECRET)
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )

    argv = _base_argv(tmp_path, **{"credentials-config": str(creds_config)})
    code, captured = run(argv, pepper_file, capsys)

    assert code == EXIT_SWEEP_OK
    heartbeat = read_heartbeat(tmp_path / "heartbeat.json")
    assert heartbeat.counts["alive"] == 1

    store = GraphStore(tmp_path / "graph.sqlite3")
    evidence = store.list_canary_evidence(fp)
    store.close()
    assert len(evidence) == 1
    assert evidence[0]["verdict"] == "alive"


# --- alert channel wiring -------------------------------------------------


def test_alert_channel_is_invoked_for_a_dead_credential(tmp_path, pepper_file, capsys):
    fp = fingerprint(PEPPER, SECRET)
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(fp, kind="api-token", rotation_class="unknown")
    store.record_canary_evidence(fp, "2026-08-18T12:00:00+00:00", "dead", 12.0, "401")
    store.close()

    marker_file = tmp_path / "alert-fired.txt"
    channel_config = tmp_path / "channel.json"
    channel_config.write_text(
        json.dumps(
            {
                "command": [
                    "python3",
                    "-c",
                    f"open(r'{marker_file}', 'w').write('{{message}}')",
                ]
            }
        )
    )

    argv = _base_argv(tmp_path, **{"alert-channel-config": str(channel_config)})
    code, captured = run(argv, pepper_file, capsys)

    assert code == EXIT_SWEEP_OK
    assert marker_file.exists()
    assert "DEAD" in marker_file.read_text()


# --- output ----------------------------------------------------------------


def test_json_output_is_valid_json(tmp_path, pepper_file, capsys):
    argv = [*_base_argv(tmp_path), "--json"]
    code, captured = run(argv, pepper_file, capsys)

    payload = json.loads(captured.out)
    assert payload["invoked_by"] == "interactive"
