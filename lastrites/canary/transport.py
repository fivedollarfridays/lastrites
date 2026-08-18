"""The side-effecting boundary: one authenticated HTTP call, normalized.

Everything above this module deals in `ProbeRequest`/`ProbeResponse` and
three exception classes -- never in `urllib` internals -- so the engine
and its tests never need a real socket.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class ProbeError(Exception):
    """Base class for anything that stopped the probe from observing."""


class ProbeTimeout(ProbeError):
    pass


class ProbeDNSError(ProbeError):
    pass


class ProbeNetworkError(ProbeError):
    pass


@dataclass(frozen=True)
class ProbeRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    body: bytes


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A canary has no reason to follow a redirect — and urllib's default
    handler re-sends every header, Authorization included, to whatever host
    the redirect names. Refusing outright turns a 3xx into a plain response,
    which the verdict layer classifies UNOBSERVABLE: the endpoint moved, the
    credential was not disproven, and the secret never chased the redirect.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_RefuseRedirects)


def send(request: ProbeRequest, timeout: float = 5.0) -> ProbeResponse:
    urllib_request = urllib.request.Request(
        request.url, data=request.body, headers=request.headers, method=request.method
    )
    try:
        with _OPENER.open(urllib_request, timeout=timeout) as response:
            return ProbeResponse(status=response.status, body=response.read())
    except urllib.error.HTTPError as exc:
        return ProbeResponse(status=exc.code, body=exc.read())
    except TimeoutError as exc:
        raise ProbeTimeout(str(exc)) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise ProbeTimeout(str(exc.reason)) from exc
        if isinstance(exc.reason, socket.gaierror):
            raise ProbeDNSError(str(exc.reason)) from exc
        raise ProbeNetworkError(str(exc.reason)) from exc
