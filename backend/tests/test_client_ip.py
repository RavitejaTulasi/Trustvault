"""Trusted client IP resolution tests."""

import pytest
from starlette.requests import Request

from backend.app.config import Settings, settings
from backend.app.security.client_ip import get_client_ip


def make_request(peer: str | None, forwarded_for: str | list[str] | None = None) -> Request:
    headers = []
    if isinstance(forwarded_for, str):
        forwarded_for = [forwarded_for]
    for value in forwarded_for or []:
        headers.append((b"x-forwarded-for", value.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers,
            "client": (peer, 12345) if peer is not None else None,
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


def test_forwarded_header_is_ignored_without_trusted_proxies(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "")

    request = make_request("203.0.113.10", "198.51.100.25")

    assert get_client_ip(request) == "203.0.113.10"


def test_untrusted_peer_cannot_spoof_forwarded_address(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request("203.0.113.10", "198.51.100.25")

    assert get_client_ip(request) == "203.0.113.10"


def test_trusted_proxy_supplies_client_address(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request("10.1.2.3", "203.0.113.10")

    assert get_client_ip(request) == "203.0.113.10"


def test_spoofed_leftmost_value_is_ignored(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request(
        "10.1.2.3",
        "198.51.100.99, 203.0.113.10, 10.2.0.5",
    )

    assert get_client_ip(request) == "203.0.113.10"


def test_duplicate_forwarded_headers_are_walked_as_one_chain(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request(
        "10.1.2.3",
        ["198.51.100.99", "203.0.113.10, 10.2.0.5"],
    )

    assert get_client_ip(request) == "203.0.113.10"


def test_rightmost_untrusted_hop_is_not_overridden(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request("10.1.2.3", "203.0.113.10, 198.51.100.20")

    assert get_client_ip(request) == "198.51.100.20"


def test_malformed_forwarded_header_falls_back_to_peer(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request("10.1.2.3", "203.0.113.10, not-an-ip")

    assert get_client_ip(request) == "10.1.2.3"


def test_oversized_forwarded_header_falls_back_to_peer(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request("10.1.2.3", "203.0.113.10, " + "1" * 3000)

    assert get_client_ip(request) == "10.1.2.3"


def test_excessive_forwarded_hops_fall_back_to_peer(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")
    header = ", ".join("203.0.113.10" for _ in range(33))

    request = make_request("10.1.2.3", header)

    assert get_client_ip(request) == "10.1.2.3"


def test_ipv6_forwarded_address_is_normalized(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "2001:db8:ffff::/48")

    request = make_request(
        "2001:db8:ffff::10",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
    )

    assert get_client_ip(request) == "2001:db8::1"


def test_missing_client_returns_none():
    request = make_request(None, "203.0.113.10")

    assert get_client_ip(request) is None


def test_trusted_proxy_without_forwarded_header_returns_peer(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "10.0.0.0/8")

    request = make_request("10.1.2.3")

    assert get_client_ip(request) == "10.1.2.3"


@pytest.mark.parametrize(
    "value",
    ["not-a-network", "10.0.0.0/8, invalid", "0.0.0.0/0", "::/0"],
)
def test_invalid_or_unbounded_proxy_allowlists_are_rejected(value: str):
    with pytest.raises(ValueError):
        Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            DATABASE_URL="sqlite:///:memory:",
            TRUSTED_PROXY_IPS=value,
        )


@pytest.mark.parametrize(
    "value",
    ["", "10.0.0.0/8", "10.0.0.1/32,2001:db8:ffff::/48"],
)
def test_valid_proxy_allowlists_are_accepted(value: str):
    configured = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite:///:memory:",
        TRUSTED_PROXY_IPS=value,
    )

    assert configured.TRUSTED_PROXY_IPS == value
