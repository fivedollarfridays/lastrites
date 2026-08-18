"""The pluggable alert channel: a configured command, never a hardcoded
endpoint.

THREAT-MODEL SS4 treats the escalation channel as part of the attack
surface, and WATCH-TOPOLOGY names the push topic itself as sensitive (its
name is the credential). Both mean the same thing here: this module never
contains a URL, a topic, or a webhook path -- it runs whatever command a
config file supplies, substituting `{message}` into each argument. The
config file is operator-owned and lives outside the repo, same as the
pepper and the credential registry. No config, no channel: a sweep still
completes and its alerts are still computed, they just cannot be sent,
and that gap is reported rather than hidden (see sweep.py).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path


def require_private_config(path: Path) -> Path:
    """This config is executed (channel) or names secret locations
    (registry) — the same trust level as a crontab. Refuse it if anyone
    but the invoking user could have written it: group/world-writable or
    foreign-owned config is an unauthenticated code-execution path.
    """
    path = Path(path)
    st = os.stat(path)
    if st.st_uid != os.geteuid():
        raise PermissionError(f"{path} is not owned by the invoking user — refusing")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"{path} is group/world-writable — refusing")
    return path


@dataclass(frozen=True)
class ChannelConfig:
    command: list[str]


def load_channel_config(path: Path) -> ChannelConfig:
    payload = json.loads(require_private_config(path).read_text())
    command = payload.get("command")
    if not isinstance(command, list) or not command:
        raise ValueError("channel config 'command' must be a non-empty list of strings")
    return ChannelConfig(command=list(command))


class ChannelError(Exception):
    """The configured channel command failed to run or exited nonzero."""


def send_alert(config: ChannelConfig, message: str, runner=subprocess.run) -> None:
    # str.replace, not str.format: format() on config-supplied templates
    # permits attribute-access gadgets ({message.__class__}) and raises on
    # any literal brace in a legitimate template (e.g. a JSON body).
    argv = [arg.replace("{message}", message) for arg in config.command]
    result = runner(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise ChannelError(
            f"alert channel command exited {result.returncode}: {result.stderr.strip()}"
        )
