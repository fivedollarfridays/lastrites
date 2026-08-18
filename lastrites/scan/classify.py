"""Provider/kind classification from key names and value shapes.

`CLOUDFLARE_API_TOKEN=` is its own documentation (DESIGN §Discovery step
5). When the evidence runs out the answer is `unknown` -- a guessed
provider sends an operator to the wrong dashboard mid-outage, which is
strictly worse than an honest blank.
"""

from __future__ import annotations

from dataclasses import dataclass

from lastrites.core.canonicalize import canonicalize_plain

UNKNOWN = "unknown"

PROVIDER_KEY_HINTS = (
    ("cloudflare", ("CLOUDFLARE", "CF_API")),
    ("aws", ("AWS_",)),
    ("github", ("GITHUB", "GH_TOKEN")),
    ("gitlab", ("GITLAB",)),
    ("stripe", ("STRIPE",)),
    ("slack", ("SLACK",)),
    ("openai", ("OPENAI",)),
    ("anthropic", ("ANTHROPIC",)),
    ("google", ("GOOGLE_", "GCP_", "GCLOUD")),
    ("datadog", ("DATADOG", "DD_API")),
    ("twilio", ("TWILIO",)),
    ("sendgrid", ("SENDGRID",)),
    ("digitalocean", ("DIGITALOCEAN", "DO_API")),
    ("npm", ("NPM_",)),
    ("pypi", ("PYPI_", "TWINE_")),
)

PROVIDER_VALUE_PREFIXES = (
    ("aws", ("AKIA", "ASIA")),
    ("github", ("ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_")),
    ("stripe", ("sk_live_", "sk_test_", "rk_live_")),
    ("slack", ("xoxb-", "xoxp-", "xoxa-", "xoxs-")),
    ("anthropic", ("sk-ant-",)),
    ("openai", ("sk-proj-",)),
    ("google", ("ya29.", "AIza")),
    ("sendgrid", ("SG.",)),
    ("npm", ("npm_",)),
    ("pypi", ("pypi-",)),
)

#: Most specific first -- ACCESS_KEY_ID must win over the bare _KEY hint.
KIND_KEY_HINTS = (
    ("access-key-id", ("ACCESS_KEY_ID", "KEY_ID")),
    ("secret-access-key", ("SECRET_ACCESS_KEY",)),
    ("private-key", ("PRIVATE_KEY",)),
    ("password", ("PASSWORD", "PASSWD", "_PASS")),
    ("api-token", ("API_TOKEN", "API_KEY", "APIKEY", "ACCESS_TOKEN", "TOKEN")),
    ("webhook-url", ("WEBHOOK_URL", "WEBHOOK_ENDPOINT")),
    # A webhook *secret* signs payloads; it is not the endpoint it signs for.
    ("signing-secret", ("SIGNING", "WEBHOOK_SECRET")),
    ("session-key", ("SESSION",)),
    ("api-key", ("_KEY",)),
    ("secret", ("SECRET",)),
)

_PEM_MARKER = "-----BEGIN"
_SERVICE_ACCOUNT_MARKER = '"service_account"'


@dataclass(frozen=True)
class Classification:
    provider: str
    kind: str
    #: LR1.3's provider registry owns this. LR1.2 refuses to invent it.
    rotation_class: str = UNKNOWN


def _match_hints(haystack: str, table) -> str | None:
    for label, hints in table:
        if any(hint in haystack for hint in hints):
            return label
    return None


def _provider_from_value(value: str) -> str | None:
    for label, prefixes in PROVIDER_VALUE_PREFIXES:
        if value.startswith(prefixes):
            return label
    if _SERVICE_ACCOUNT_MARKER in value:
        return "google"
    return None


def _kind_from_value(value: str) -> str | None:
    if _PEM_MARKER in value and "PRIVATE KEY" in value:
        return "private-key"
    if _SERVICE_ACCOUNT_MARKER in value:
        return "service-account-json"
    return None


def classify(key: str, value: str) -> Classification:
    """Name the provider and kind, or say `unknown`. Key name outranks shape."""
    key_upper = key.upper()
    candidate = canonicalize_plain(value)

    provider = _match_hints(key_upper, PROVIDER_KEY_HINTS) or _provider_from_value(
        candidate
    )
    kind = _match_hints(key_upper, KIND_KEY_HINTS) or _kind_from_value(candidate)
    return Classification(provider=provider or UNKNOWN, kind=kind or UNKNOWN)
