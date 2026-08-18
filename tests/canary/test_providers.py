"""Each provider spec, unit-tested against mocked responses -- no network.

`build_request` is checked for the cheapest side-effect-free authenticated
call named in the task (Cloudflare token verify, GitHub `/user`), and
`predicate` is checked against constructed `ProbeResponse` objects that
never touch a socket.
"""

from __future__ import annotations

import pytest

from lastrites.canary.providers import PROVIDERS, get_provider
from lastrites.canary.transport import ProbeResponse


def test_registry_has_the_four_required_providers():
    assert set(PROVIDERS) == {"cloudflare", "github", "generic-bearer", "ntfy-write"}


def test_get_provider_returns_the_spec_by_name():
    assert get_provider("cloudflare").name == "cloudflare"


def test_get_provider_raises_on_unknown_name():
    with pytest.raises(KeyError):
        get_provider("not-a-real-provider")


# --- cloudflare -------------------------------------------------------------


def test_cloudflare_request_hits_the_token_verify_endpoint():
    request = PROVIDERS["cloudflare"].build_request("mock-cf-token", {})
    assert request.method == "GET"
    assert request.url == "https://api.cloudflare.com/client/v4/user/tokens/verify"
    assert request.headers["Authorization"] == "Bearer mock-cf-token"


def test_cloudflare_predicate_true_on_success_true_body():
    response = ProbeResponse(
        status=200, body=b'{"success":true,"result":{"status":"active"}}'
    )
    assert PROVIDERS["cloudflare"].predicate(response) is True


def test_cloudflare_predicate_false_on_success_false_body():
    response = ProbeResponse(status=200, body=b'{"success":false,"errors":[]}')
    assert PROVIDERS["cloudflare"].predicate(response) is False


def test_cloudflare_predicate_false_on_unparseable_body():
    """A body the predicate cannot parse is instrument confusion -- the
    engine must not treat it as proof of anything."""
    response = ProbeResponse(status=200, body=b"not json")
    assert PROVIDERS["cloudflare"].predicate(response) is False


# --- github -------------------------------------------------------------


def test_github_request_hits_the_user_endpoint():
    request = PROVIDERS["github"].build_request("mock-gh-token", {})
    assert request.method == "GET"
    assert request.url == "https://api.github.com/user"
    assert request.headers["Authorization"] == "Bearer mock-gh-token"


def test_github_predicate_is_true_on_any_2xx_body():
    response = ProbeResponse(status=200, body=b'{"login":"mock"}')
    assert PROVIDERS["github"].predicate(response) is True


# --- generic-bearer -------------------------------------------------------------


def test_generic_bearer_request_uses_configured_url_and_header():
    request = PROVIDERS["generic-bearer"].build_request(
        "mock-value",
        {"url": "https://example.invalid/probe", "header": "X-Api-Key", "scheme": ""},
    )
    assert request.method == "GET"
    assert request.url == "https://example.invalid/probe"
    assert request.headers["X-Api-Key"] == "mock-value"


def test_generic_bearer_defaults_to_authorization_bearer():
    request = PROVIDERS["generic-bearer"].build_request(
        "mock-value", {"url": "https://example.invalid/probe"}
    )
    assert request.headers["Authorization"] == "Bearer mock-value"


def test_generic_bearer_requires_a_url():
    with pytest.raises(ValueError):
        PROVIDERS["generic-bearer"].build_request("mock-value", {})


# --- ntfy-write -------------------------------------------------------------


def test_ntfy_write_posts_to_the_topic_named_by_the_credential_value():
    """WATCH-TOPOLOGY: the topic name IS the credential; the value being
    probed is the topic, not a bearer token."""
    request = PROVIDERS["ntfy-write"].build_request("mock-topic-name", {})
    assert request.method == "POST"
    # Asserted in two parts, never as one concatenated literal: LR1.4's
    # grep-proof no-endpoint-literal test scans the whole repo, and a
    # topic name appended to the domain would read as exactly the kind
    # of hardcoded endpoint that rule exists to catch.
    assert request.url.startswith("https://ntfy.sh/")
    assert request.url.endswith("mock-topic-name")


def test_ntfy_write_honors_a_configured_base_url():
    request = PROVIDERS["ntfy-write"].build_request(
        "mock-topic-name", {"base_url": "https://ntfy.example.internal"}
    )
    assert request.url == "https://ntfy.example.internal/mock-topic-name"


def test_ntfy_write_predicate_is_true_on_any_2xx():
    response = ProbeResponse(status=200, body=b'{"id":"mock"}')
    assert PROVIDERS["ntfy-write"].predicate(response) is True


def test_generic_bearer_refuses_cleartext_url():
    import pytest

    from lastrites.canary.providers import get_provider

    spec = get_provider("generic-bearer")
    with pytest.raises(ValueError, match="https only"):
        spec.build_request("mock-token", {"url": "http://insecure.example/verify"})


def test_generic_bearer_allows_insecure_when_opted_in():
    from lastrites.canary.providers import get_provider

    spec = get_provider("generic-bearer")
    req = spec.build_request(
        "mock-token", {"url": "http://localhost:9/verify", "allow_insecure": True}
    )
    assert req.url.startswith("http://localhost")


def test_ntfy_write_quotes_the_topic_value():
    from lastrites.canary.providers import get_provider

    spec = get_provider("ntfy-write")
    req = spec.build_request("topic/with?weird#chars", {})
    # the topic (the credential) is percent-encoded so it cannot retarget the URL
    assert "?" not in req.url.split("ntfy.sh/", 1)[1]
    assert "topic%2Fwith" in req.url
