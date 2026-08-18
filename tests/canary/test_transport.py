"""The one module allowed to touch a real socket.

Everything here monkeypatches `urllib.request.urlopen` -- no test in this
suite makes a real network call. `send()`'s job is normalization: an
HTTP-level response (even 401/403) comes back as a `ProbeResponse`, while
a failure to observe anything at all (timeout, DNS, connection refused)
raises one of three typed exceptions the verdict layer already knows how
to classify.
"""

from __future__ import annotations

import socket
import urllib.error

import pytest

from lastrites.canary.transport import (
    ProbeDNSError,
    ProbeNetworkError,
    ProbeRequest,
    ProbeResponse,
    ProbeTimeout,
    send,
)


class _FakeOpenResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _install_urlopen(monkeypatch, fn):
    # send() routes through a redirect-refusing opener (a canary must never
    # chase a redirect and forward its Authorization header to a new host);
    # patch that opener's .open, which is the real seam now.
    monkeypatch.setattr("lastrites.canary.transport._OPENER.open", fn)


def test_send_returns_a_response_on_success(monkeypatch):
    _install_urlopen(
        monkeypatch, lambda req, timeout=None: _FakeOpenResponse(200, b'{"ok":true}')
    )
    response = send(ProbeRequest(method="GET", url="https://example.invalid/x"))
    assert response == ProbeResponse(status=200, body=b'{"ok":true}')


def test_send_normalizes_an_http_error_status_into_a_response(monkeypatch):
    """401/403 are legitimate application-level answers, not transport
    failures -- the verdict layer needs to see the status, not an
    exception, to tell DEAD from UNOBSERVABLE."""

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    _install_urlopen(monkeypatch, fake_urlopen)
    response = send(ProbeRequest(method="GET", url="https://example.invalid/x"))
    assert response.status == 401


def test_send_raises_probe_timeout_on_socket_timeout(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise socket.timeout("timed out")

    _install_urlopen(monkeypatch, fake_urlopen)
    with pytest.raises(ProbeTimeout):
        send(ProbeRequest(method="GET", url="https://example.invalid/x"))


def test_send_raises_probe_dns_error_on_gaierror(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError(socket.gaierror("Name or service not known"))

    _install_urlopen(monkeypatch, fake_urlopen)
    with pytest.raises(ProbeDNSError):
        send(ProbeRequest(method="GET", url="https://example.invalid/x"))


def test_send_raises_probe_network_error_on_other_url_errors(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError(ConnectionRefusedError("connection refused"))

    _install_urlopen(monkeypatch, fake_urlopen)
    with pytest.raises(ProbeNetworkError):
        send(ProbeRequest(method="GET", url="https://example.invalid/x"))


def test_send_builds_the_request_with_method_headers_and_body(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data
        captured["timeout"] = timeout
        return _FakeOpenResponse(200, b"")

    _install_urlopen(monkeypatch, fake_urlopen)
    send(
        ProbeRequest(
            method="POST",
            url="https://example.invalid/topic",
            headers={"Title": "canary probe"},
            body=b"ping",
        ),
        timeout=3.0,
    )
    assert captured["method"] == "POST"
    assert captured["headers"]["Title"] == "canary probe"
    assert captured["data"] == b"ping"
    assert captured["timeout"] == 3.0


def test_send_refuses_to_follow_redirects(monkeypatch):
    """A canary must not chase a 3xx: urllib's default handler re-sends the
    Authorization header to the redirect's host. The refusing opener turns a
    redirect into a returned response the verdict layer reads as UNOBSERVABLE,
    and the credential never leaves for the new host."""
    from lastrites.canary.transport import ProbeRequest, _RefuseRedirects

    handler = _RefuseRedirects()
    assert (
        handler.redirect_request(None, None, 302, "Found", {}, "http://evil.example")
        is None
    )
    # sanity: the request path still carries the auth header we would protect
    req = ProbeRequest(
        method="GET", url="https://x", headers={"Authorization": "Bearer mock"}
    )
    assert req.headers["Authorization"] == "Bearer mock"
