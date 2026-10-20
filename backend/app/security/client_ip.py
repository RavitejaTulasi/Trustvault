"""
Trusted Client IP Resolution
Resolves the requesting client address without trusting client-supplied forwarding
headers unless the immediate peer is an explicitly configured trusted proxy.
"""

import ipaddress
from functools import lru_cache
from typing import TypeAlias

from fastapi import Request

from backend.app.config import settings

IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_FORWARDED_HEADER_LENGTH = 2048
MAX_FORWARDED_HOPS = 32


@lru_cache(maxsize=8)
def _parse_trusted_networks(raw_value: str) -> tuple[IPNetwork, ...]:
    """Parse the configured proxy allowlist once per distinct setting value."""
    networks: list[IPNetwork] = []
    for entry in raw_value.split(","):
        candidate = entry.strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            # Startup validation rejects malformed entries. If this module is
            # used with an overridden setting, fail closed by ignoring them.
            continue
    return tuple(networks)


def _parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _is_trusted_proxy(address: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    return any(address in network for network in networks)


def _parse_forwarded_chain(header: str) -> list[IPAddress] | None:
    """
    Parse an X-Forwarded-For chain conservatively.

    Any malformed entry, excessive length, or excessive hop count causes the
    entire header to be ignored so a crafted value cannot influence attribution.
    """
    if len(header) > MAX_FORWARDED_HEADER_LENGTH:
        return None

    entries = header.split(",")
    if not entries or len(entries) > MAX_FORWARDED_HOPS:
        return None

    chain: list[IPAddress] = []
    for entry in entries:
        address = _parse_ip(entry)
        if address is None:
            return None
        chain.append(address)
    return chain


def get_client_ip(request: Request) -> str | None:
    """
    Return the best trustworthy client address for a request.

    The immediate peer is authoritative unless it matches TRUSTED_PROXY_IPS.
    For a trusted peer, X-Forwarded-For is walked right-to-left and traversal
    stops at the first address that is not itself a configured proxy. This
    ignores attacker-supplied leftmost values while preserving legitimate
    multi-proxy chains.
    """
    if request.client is None:
        return None

    peer_raw = request.client.host
    peer = _parse_ip(peer_raw)
    if peer is None:
        return peer_raw

    networks = _parse_trusted_networks(settings.TRUSTED_PROXY_IPS)
    if not networks or not _is_trusted_proxy(peer, networks):
        return str(peer)

    forwarded_values = request.headers.getlist("X-Forwarded-For")
    if not forwarded_values:
        return str(peer)

    chain = _parse_forwarded_chain(",".join(forwarded_values))
    if chain is None:
        return str(peer)

    resolved: IPAddress = peer
    for candidate in reversed(chain):
        if not _is_trusted_proxy(resolved, networks):
            break
        resolved = candidate

    return str(resolved)
