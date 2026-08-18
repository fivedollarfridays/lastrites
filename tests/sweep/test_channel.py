"""The pluggable alert channel: a configured command, never a literal
endpoint. No test in this file, or anywhere else, may embed a real
alerting endpoint or topic -- `test_no_endpoint_literals.py` enforces
that across the whole repo.
"""

from __future__ import annotations

import json

import pytest

from lastrites.sweep.channel import ChannelError, load_channel_config, send_alert


def test_load_channel_config_parses_a_command_list(tmp_path):
    path = tmp_path / "channel.json"
    path.write_text(
        json.dumps(
            {
                "command": [
                    "curl",
                    "-fsS",
                    "-d",
                    "{message}",
                    "https://example.invalid/alert",
                ]
            }
        )
    )
    config = load_channel_config(path)
    assert config.command == [
        "curl",
        "-fsS",
        "-d",
        "{message}",
        "https://example.invalid/alert",
    ]


def test_load_channel_config_rejects_non_list_command(tmp_path):
    path = tmp_path / "channel.json"
    path.write_text(json.dumps({"command": "curl"}))
    with pytest.raises(ValueError, match="command"):
        load_channel_config(path)


def test_load_channel_config_rejects_empty_command(tmp_path):
    path = tmp_path / "channel.json"
    path.write_text(json.dumps({"command": []}))
    with pytest.raises(ValueError, match="command"):
        load_channel_config(path)


def test_send_alert_formats_message_into_each_argument(tmp_path):
    path = tmp_path / "channel.json"
    path.write_text(
        json.dumps({"command": ["notify", "--text", "{message}", "--tag={message}"]})
    )
    config = load_channel_config(path)

    calls = []

    def fake_runner(argv, **kwargs):
        calls.append(argv)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    send_alert(config, "credential dead", runner=fake_runner)
    assert calls == [["notify", "--text", "credential dead", "--tag=credential dead"]]


def test_send_alert_raises_on_nonzero_exit(tmp_path):
    path = tmp_path / "channel.json"
    path.write_text(json.dumps({"command": ["notify", "{message}"]}))
    config = load_channel_config(path)

    def failing_runner(argv, **kwargs):
        class Result:
            returncode = 1
            stderr = "connection refused"

        return Result()

    with pytest.raises(ChannelError, match="connection refused"):
        send_alert(config, "credential dead", runner=failing_runner)
