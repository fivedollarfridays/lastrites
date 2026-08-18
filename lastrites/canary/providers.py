"""Provider registry: provider -> the cheapest side-effect-free
authenticated call that proves a credential is still alive.

Three read probes (cloudflare, github, generic-bearer) and one write
probe (ntfy-write, the motivating credential class from
docs/WATCH-TOPOLOGY.md -- an unauthenticated-broadcast topic whose name
IS the credential, so "verify" means publishing to it, not reading
something back).
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Callable

from lastrites.canary.transport import ProbeRequest, ProbeResponse


def _require_https(url: str, config: dict) -> str:
    """A probe URL carries a live credential; cleartext transport hands it
    to the network. https is mandatory unless the operator explicitly opts
    out per-credential (`allow_insecure: true` — for e.g. a localhost
    test target), and the opt-out is theirs to audit, not ours to default.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme != "https" and config.get("allow_insecure") is not True:
        raise ValueError(
            f"probe URL scheme {scheme!r} refused: credentials travel over "
            "https only (set allow_insecure: true to override, audited to you)"
        )
    return url


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    build_request: Callable[[str, dict], ProbeRequest]
    predicate: Callable[[ProbeResponse], bool]


def _any_2xx(response: ProbeResponse) -> bool:
    return True


# --- cloudflare -------------------------------------------------------------


def _cloudflare_request(value: str, config: dict) -> ProbeRequest:
    return ProbeRequest(
        method="GET",
        url="https://api.cloudflare.com/client/v4/user/tokens/verify",
        headers={"Authorization": f"Bearer {value}"},
    )


def _cloudflare_predicate(response: ProbeResponse) -> bool:
    try:
        payload = json.loads(response.body)
    except (ValueError, TypeError):
        return False
    return payload.get("success") is True


# --- github -------------------------------------------------------------


def _github_request(value: str, config: dict) -> ProbeRequest:
    return ProbeRequest(
        method="GET",
        url="https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {value}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "lastrites-canary",
        },
    )


# --- generic-bearer -------------------------------------------------------------


def _generic_bearer_request(value: str, config: dict) -> ProbeRequest:
    url = config.get("url")
    if not url:
        raise ValueError("generic-bearer probe requires config['url']")
    header = config.get("header", "Authorization")
    scheme = config.get("scheme", "Bearer ")
    return ProbeRequest(
        method=config.get("method", "GET"),
        url=_require_https(url, config),
        headers={header: f"{scheme}{value}"},
    )


# --- ntfy-write -------------------------------------------------------------


def _ntfy_write_request(value: str, config: dict) -> ProbeRequest:
    base_url = config.get("base_url", "https://ntfy.sh").rstrip("/")
    message = config.get("message", "lastrites canary probe")
    # The topic IS the credential; quote it so a value containing /, ? or #
    # cannot silently retarget the request.
    topic = urllib.parse.quote(value, safe="")
    return ProbeRequest(
        method="POST",
        url=_require_https(f"{base_url}/{topic}", config),
        headers={"Title": "lastrites canary probe", "Tags": "robot", "Priority": "min"},
        body=message.encode("utf-8"),
    )


PROVIDERS: dict[str, ProviderSpec] = {
    "cloudflare": ProviderSpec(
        "cloudflare", _cloudflare_request, _cloudflare_predicate
    ),
    "github": ProviderSpec("github", _github_request, _any_2xx),
    "generic-bearer": ProviderSpec("generic-bearer", _generic_bearer_request, _any_2xx),
    "ntfy-write": ProviderSpec("ntfy-write", _ntfy_write_request, _any_2xx),
}


def get_provider(name: str) -> ProviderSpec:
    try:
        return PROVIDERS[name]
    except KeyError:
        raise KeyError(f"unknown canary provider: {name!r}") from None
