"""The three-way verdict distinction (THREAT-MODEL doctrine):

The instrument being blind is never reported as the surface being dead.
Only an authenticated 401/403 earns DEAD; every network failure the
canary cannot see past (timeout, DNS, 5xx, an ambiguous status) is
UNOBSERVABLE, never DEAD.
"""

import pytest

from lastrites.canary.models import Verdict
from lastrites.canary.transport import ProbeDNSError, ProbeNetworkError, ProbeTimeout
from lastrites.canary.verdict import classify_error, classify_response


# --- classify_response: status code + predicate -> verdict ----------------


@pytest.mark.parametrize("status", [401, 403])
def test_401_and_403_are_dead(status):
    verdict, http_class = classify_response(status, predicate_ok=False)
    assert verdict is Verdict.DEAD
    assert http_class == str(status)


def test_2xx_with_predicate_true_is_alive():
    verdict, http_class = classify_response(200, predicate_ok=True)
    assert verdict is Verdict.ALIVE
    assert http_class == "200"


def test_2xx_with_predicate_false_is_unobservable_not_dead():
    """A 2xx that fails the success predicate is instrument confusion, not
    proof the credential is dead."""
    verdict, _ = classify_response(200, predicate_ok=False)
    assert verdict is Verdict.UNOBSERVABLE


@pytest.mark.parametrize("status", [500, 502, 503])
def test_5xx_is_unobservable(status):
    verdict, http_class = classify_response(status, predicate_ok=False)
    assert verdict is Verdict.UNOBSERVABLE
    assert http_class == str(status)


@pytest.mark.parametrize("status", [400, 404, 429])
def test_other_4xx_is_unobservable_not_dead(status):
    """Only 401/403 is an authenticated rejection. A 404/429/400 does not
    prove the credential is dead -- reporting DEAD here would be the
    instrument's confusion mislabeled as the surface's death."""
    verdict, _ = classify_response(status, predicate_ok=False)
    assert verdict is Verdict.UNOBSERVABLE


# --- classify_error: network failure -> always unobservable ---------------


def test_timeout_is_unobservable():
    verdict, http_class = classify_error(ProbeTimeout("timed out"))
    assert verdict is Verdict.UNOBSERVABLE
    assert http_class == "timeout"


def test_dns_failure_is_unobservable():
    verdict, http_class = classify_error(ProbeDNSError("name not known"))
    assert verdict is Verdict.UNOBSERVABLE
    assert http_class == "dns"


def test_generic_network_error_is_unobservable():
    verdict, http_class = classify_error(ProbeNetworkError("connection refused"))
    assert verdict is Verdict.UNOBSERVABLE
    assert http_class == "network-error"


def test_no_network_failure_ever_classifies_as_dead():
    """Pin the doctrine directly: nothing reachable through classify_error
    can produce DEAD. Only an authenticated 401/403 response can."""
    for exc in (ProbeTimeout("t"), ProbeDNSError("d"), ProbeNetworkError("n")):
        verdict, _ = classify_error(exc)
        assert verdict is not Verdict.DEAD
