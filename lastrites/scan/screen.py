"""Candidate screening: is this assignment plausibly a secret?

Tuned to over-collect (DESIGN §Discovery step 2). A false candidate costs
one wasted fingerprint; a missed one is a copy the graph never learns
about, which is the failure this whole project exists to prevent. But
over-collecting is not collecting everything -- a scan that flags PATH
trains its operator to ignore the scan, so the obvious non-secrets are
excluded by named rules, and every rejection says which rule fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from lastrites.core.canonicalize import canonicalize_plain
from lastrites.scan.entropy import shannon_entropy

MIN_LENGTH = 12
#: An explicitly secret-shaped key name is strong enough evidence to beat the
#: length floor -- `DB_PASSWORD=hunter2` is a credential and a short one is
#: worse, not less real. The floor stays above zero because an empty value
#: would fingerprint identically everywhere and cluster unrelated surfaces.
HINTED_MIN_LENGTH = 4
MIN_ENTROPY = 3.0
#: Below this length, an all-alphabetic value is a word, not a token.
ALPHA_WORD_MAX = 32

#: Environment names that are structurally incapable of being secrets.
#: The second group are well-known names that DO contain a hint word
#: (`SSH_AUTH_SOCK`, `SESSION_MANAGER`) and would otherwise be rescued by it.
NON_SECRET_KEYS = frozenset(
    {
        "PATH",
        "MANPATH",
        "PYTHONPATH",
        "NODE_PATH",
        "GOPATH",
        "CLASSPATH",
        "HOME",
        "PWD",
        "OLDPWD",
        "TMPDIR",
        "SHELL",
        "USER",
        "LOGNAME",
        "TERM",
        "LANG",
        "LC_ALL",
        "TZ",
        "DISPLAY",
        "SHLVL",
        "HOSTNAME",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "MAILTO",
        "MAILFROM",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "GPG_AGENT_INFO",
        "SESSION_MANAGER",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_ID",
        "XDG_SESSION_TYPE",
        "XDG_SESSION_CLASS",
        "TERM_SESSION_ID",
        "ITERM_SESSION_ID",
    }
)

#: Whole `_`-separated WORDS that make a key name its own documentation.
#: Matched as tokens, not substrings, so `AUTHOR` is not `AUTH` and
#: `MONKEY_COUNT` is not `KEY`.
SECRET_KEY_HINTS = frozenset(
    {
        "TOKEN",
        "TOKENS",
        "SECRET",
        "SECRETS",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PASSPHRASE",
        "APIKEY",
        "KEY",
        "KEYS",
        "CREDENTIAL",
        "CREDENTIALS",
        "AUTH",
        "BEARER",
        "WEBHOOK",
        "PRIVATE",
        "SALT",
        "DSN",
        "SESSION",
        "SIGNING",
        "SIGNATURE",
        "CERT",
        "PIN",
        "OTP",
    }
)

#: Values that carry no information about the machine they sit on. A hint
#: must NOT rescue these: identical literals fingerprint identically, so
#: collecting them manufactures fake credentials whose copy counts outrank
#: every real one -- the blast-radius signal inverted, permanently, because
#: the graph has no delete path.
CONFIG_LITERALS = frozenset(
    {
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "none",
        "null",
        "nil",
        "enabled",
        "disabled",
        "required",
        "optional",
        "auto",
        "default",
        "always",
        "never",
        "debug",
        "info",
        "warn",
        "warning",
        "error",
    }
)

#: Key names that point AT a secret rather than holding one --
#: `SSH_KEY_PATH=/home/mockuser/.ssh/id_rsa` is a path, not the key. These
#: suffixes forfeit the hint, so the path rule below can do its job.
LOCATION_KEY_SUFFIXES = ("_PATH", "_FILE", "_DIR", "_HOME", "_ROOT", "_LOCATION")

_PATH_PREFIXES = ("/", "~/", "./", "../")
_STRUCTURED_PREFIXES = ("{", "[")
_PEM_MARKER = "-----BEGIN"


@dataclass(frozen=True)
class ScreenResult:
    accepted: bool
    reason: str


#: One separator is not a path. Real AWS secret access keys are base64 and
#: begin with `/` about one time in 64; `/var/log/app` has two. Counting
#: separators keeps the path rule from eating exactly those secrets.
MIN_PATH_SEPARATORS = 2


def _looks_like_path(value: str) -> bool:
    if "://" in value:
        return True
    return value.startswith(_PATH_PREFIXES) and value.count("/") >= MIN_PATH_SEPARATORS


def _is_structured(value: str) -> bool:
    return value.startswith(_STRUCTURED_PREFIXES) or _PEM_MARKER in value


def _is_config_literal(value: str) -> bool:
    return value.isdigit() or value.lower() in CONFIG_LITERALS


def _hints_secret(key_upper: str) -> bool:
    if key_upper.endswith(LOCATION_KEY_SUFFIXES):
        return False
    return not SECRET_KEY_HINTS.isdisjoint(re.split(r"[^A-Z0-9]+", key_upper))


def screen_candidate(key: str, value: str) -> ScreenResult:
    """Decide whether `key=value` is worth fingerprinting, and say why.

    Rule order is the whole design.

    Two rules outrank everything, including an explicit key name. A name in
    `NON_SECRET_KEYS` is not a secret whatever it contains, and a value in
    `CONFIG_LITERALS` is not a secret whatever it is called -- `true` under
    `AUTH_ENABLED` must never be collected, because shared literals cluster
    and a fake credential with 40 copies buries the real one with 3.

    After that, a name the operator wrote on purpose (`AWS_SECRET_ACCESS_KEY`)
    is better evidence than any shape heuristic, so the hint is consulted
    before the length floor, the path rule and the entropy floor. Everything
    unhinted falls through to shape.
    """
    key_upper = key.upper()
    candidate = canonicalize_plain(value)

    if key_upper in NON_SECRET_KEYS:
        return ScreenResult(False, f"non-secret key name: {key_upper}")
    if _is_config_literal(candidate):
        return ScreenResult(False, "configuration literal, not a secret")
    if _hints_secret(key_upper):
        if len(candidate) < HINTED_MIN_LENGTH:
            return ScreenResult(False, f"shorter than {HINTED_MIN_LENGTH} characters")
        if _looks_like_path(candidate):
            return ScreenResult(False, "filesystem path")
        return ScreenResult(True, "key-name hint")
    if len(candidate) < MIN_LENGTH:
        return ScreenResult(False, f"shorter than {MIN_LENGTH} characters")
    if _looks_like_path(candidate):
        return ScreenResult(False, "filesystem path")

    if not _is_structured(candidate):
        if any(char.isspace() for char in candidate):
            return ScreenResult(False, "contains whitespace")
        if candidate.isalpha() and len(candidate) < ALPHA_WORD_MAX:
            return ScreenResult(False, "alphabetic word")

    entropy = shannon_entropy(candidate)
    if entropy < MIN_ENTROPY:
        return ScreenResult(
            False, f"entropy {entropy:.2f} below {MIN_ENTROPY:.2f} bits/char"
        )
    return ScreenResult(True, f"entropy {entropy:.2f} bits/char")
