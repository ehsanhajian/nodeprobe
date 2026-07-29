"""SSRF and target safety controls."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}


class UnsafeTargetError(ValueError):
    """Raised when a scan target is blocked by safety policy."""


@dataclass
class SafeTarget:
    original_url: str
    sanitized_url: str
    hostname: str
    port: int
    scheme: str
    resolved_ips: list[str]


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
            # Cloud metadata commonly used ranges
            ip in ipaddress.ip_network("169.254.0.0/16"),
            ip in ipaddress.ip_network("fd00::/8"),
        ]
    )


def mask_credentials(url: str) -> str:
    parsed = urlparse(url)
    if parsed.password or parsed.username:
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        user = parsed.username or ""
        if user:
            netloc = f"***@{netloc}"
        return urlunparse(parsed._replace(netloc=netloc))
    # Mask common token query params without logging secrets
    if "apiKey=" in url or "token=" in url or "apikey=" in url.lower():
        return url.split("?")[0] + "?[redacted]"
    return url


def validate_target(
    url: str,
    *,
    allow_http: bool = True,
    resolve_dns: bool = True,
) -> SafeTarget:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTargetError("Only http and https RPC endpoints are allowed")
    if parsed.scheme == "http" and not allow_http:
        raise UnsafeTargetError("HTTP endpoints are not allowed for this profile")
    if not parsed.hostname:
        raise UnsafeTargetError("URL must include a hostname")
    if parsed.username or parsed.password:
        # Still allow scanning but sanitize; credentials in URLs are risky
        pass

    hostname = parsed.hostname.lower()
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".localhost"):
        raise UnsafeTargetError(f"Blocked hostname: {hostname}")

    # Block literal IPs that are private/reserved
    try:
        literal_ip = ipaddress.ip_address(hostname)
        if _is_blocked_ip(literal_ip):
            raise UnsafeTargetError(f"Blocked IP address: {hostname}")
        resolved = [str(literal_ip)]
    except ValueError:
        if resolve_dns:
            resolved = _resolve_and_validate(hostname)
        else:
            resolved = []

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sanitized = mask_credentials(url)
    return SafeTarget(
        original_url=url,
        sanitized_url=sanitized,
        hostname=hostname,
        port=port,
        scheme=parsed.scheme,
        resolved_ips=resolved,
    )


def _resolve_and_validate(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"DNS resolution failed for {hostname}: {exc}") from exc

    ips: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        ip = ipaddress.ip_address(ip_str)
        if _is_blocked_ip(ip):
            raise UnsafeTargetError(
                f"Hostname {hostname} resolves to blocked address {ip_str}"
            )
        if ip_str not in ips:
            ips.append(ip_str)
    if not ips:
        raise UnsafeTargetError(f"No usable addresses for {hostname}")
    return ips


def validate_redirect_target(url: str) -> SafeTarget:
    """Re-validate redirect destinations; never follow to private ranges."""
    return validate_target(url, allow_http=True)
