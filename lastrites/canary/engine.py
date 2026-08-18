"""Runs one probe: spec -> request -> transport -> verdict.

The predicate only ever sees a 2xx response. A provider's success
predicate is written assuming a well-formed success body -- running it
against a 401/403/5xx body is exactly the kind of instrument confusion
THREAT-MODEL.md warns against, so the engine never lets that happen.
"""

from __future__ import annotations

import time

from lastrites.canary import transport as transport_module
from lastrites.canary.models import ProbeOutcome
from lastrites.canary.providers import ProviderSpec
from lastrites.canary.verdict import classify_error, classify_response


def run_probe(
    spec: ProviderSpec,
    value: str,
    config: dict | None = None,
    timeout: float = 5.0,
    transport=None,
) -> ProbeOutcome:
    config = config or {}
    request = spec.build_request(value, config)
    send = transport or transport_module.send

    started = time.monotonic()
    try:
        response = send(request, timeout=timeout)
    except transport_module.ProbeError as exc:
        latency_ms = (time.monotonic() - started) * 1000
        verdict, http_class = classify_error(exc)
        return ProbeOutcome(
            verdict=verdict, latency_ms=latency_ms, http_class=http_class
        )

    latency_ms = (time.monotonic() - started) * 1000
    predicate_ok = 200 <= response.status < 300 and spec.predicate(response)
    verdict, http_class = classify_response(response.status, predicate_ok)
    return ProbeOutcome(verdict=verdict, latency_ms=latency_ms, http_class=http_class)
