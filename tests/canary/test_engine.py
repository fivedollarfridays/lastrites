"""`run_probe` end-to-end with a fake transport -- no real socket, no
real provider. Pins that the three-way verdict distinction survives the
full path: spec -> request -> transport -> classify -> ProbeOutcome.
"""

from __future__ import annotations

from lastrites.canary.engine import run_probe
from lastrites.canary.models import ProbeOutcome, Verdict
from lastrites.canary.providers import ProviderSpec
from lastrites.canary.transport import (
    ProbeDNSError,
    ProbeRequest,
    ProbeResponse,
    ProbeTimeout,
)

SPEC = ProviderSpec(
    name="mock",
    build_request=lambda value, config: ProbeRequest(
        method="GET", url="https://example.invalid/x"
    ),
    predicate=lambda response: response.body == b"ok",
)


def _fake_transport(response=None, exc=None):
    def transport(request, timeout=None):
        if exc is not None:
            raise exc
        return response

    return transport


def test_alive_on_2xx_with_predicate_true():
    transport = _fake_transport(response=ProbeResponse(status=200, body=b"ok"))
    outcome = run_probe(SPEC, "mock-value", transport=transport)
    assert outcome.verdict is Verdict.ALIVE
    assert outcome.http_class == "200"


def test_dead_on_401():
    transport = _fake_transport(response=ProbeResponse(status=401, body=b"no"))
    outcome = run_probe(SPEC, "mock-value", transport=transport)
    assert outcome.verdict is Verdict.DEAD


def test_unobservable_on_timeout():
    transport = _fake_transport(exc=ProbeTimeout("timed out"))
    outcome = run_probe(SPEC, "mock-value", transport=transport)
    assert outcome.verdict is Verdict.UNOBSERVABLE
    assert outcome.http_class == "timeout"


def test_unobservable_on_dns_failure():
    transport = _fake_transport(exc=ProbeDNSError("nope"))
    outcome = run_probe(SPEC, "mock-value", transport=transport)
    assert outcome.verdict is Verdict.UNOBSERVABLE
    assert outcome.http_class == "dns"


def test_unobservable_on_2xx_with_predicate_false():
    transport = _fake_transport(response=ProbeResponse(status=200, body=b"not-ok"))
    outcome = run_probe(SPEC, "mock-value", transport=transport)
    assert outcome.verdict is Verdict.UNOBSERVABLE


def test_predicate_is_not_called_on_non_2xx_status():
    """A predicate that assumes a well-formed success body must never run
    against a 401/403/5xx body -- that is how instrument confusion leaks
    into a false verdict."""

    def explosive_predicate(response):
        raise AssertionError("predicate must not run on a non-2xx response")

    spec = ProviderSpec(
        name="mock", build_request=SPEC.build_request, predicate=explosive_predicate
    )
    transport = _fake_transport(response=ProbeResponse(status=500, body=b"boom"))
    outcome = run_probe(spec, "mock-value", transport=transport)
    assert outcome.verdict is Verdict.UNOBSERVABLE


def test_outcome_carries_a_non_negative_latency():
    transport = _fake_transport(response=ProbeResponse(status=200, body=b"ok"))
    outcome = run_probe(SPEC, "mock-value", transport=transport)
    assert isinstance(outcome, ProbeOutcome)
    assert outcome.latency_ms >= 0


def test_config_is_passed_through_to_build_request():
    seen = {}

    def build_request(value, config):
        seen["value"] = value
        seen["config"] = config
        return ProbeRequest(method="GET", url="https://example.invalid/x")

    spec = ProviderSpec(
        name="mock", build_request=build_request, predicate=lambda r: True
    )
    transport = _fake_transport(response=ProbeResponse(status=200, body=b""))
    run_probe(
        spec,
        "mock-value",
        config={"url": "https://example.invalid/custom"},
        transport=transport,
    )
    assert seen["value"] == "mock-value"
    assert seen["config"] == {"url": "https://example.invalid/custom"}
