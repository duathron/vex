"""Auto-detection of IOC type from raw string."""

import ipaddress
import re
from enum import Enum

from .defang import is_defanged, refang


class IOCType(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    UNKNOWN = "unknown"


_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def detect(ioc: str) -> tuple[IOCType, str]:
    """Detect the type of an IOC string and return the normalised value.

    Automatically refangs defanged IOCs before detection so that
    inputs like ``hxxps[://]evil[.]com`` are recognised correctly.

    Returns:
        ``(IOCType, normalised_ioc)`` — the IOC is stripped and refanged.
    """
    value = ioc.strip()
    if is_defanged(value):
        value = refang(value)
    if _MD5_RE.match(value):
        return IOCType.MD5, value
    if _SHA1_RE.match(value):
        return IOCType.SHA1, value
    if _SHA256_RE.match(value):
        return IOCType.SHA256, value
    if _IPV4_RE.match(value):
        return IOCType.IPV4, value
    # IPv6: use stdlib ipaddress for full RFC 4291 compliance
    ipv6_candidate = value.split("%")[0]  # strip zone ID (e.g. fe80::1%eth0)
    try:
        addr = ipaddress.ip_address(ipv6_candidate)
        if isinstance(addr, ipaddress.IPv6Address):
            return IOCType.IPV6, str(addr)  # canonical compressed form
    except ValueError:
        pass
    if _URL_RE.match(value):
        return IOCType.URL, value
    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN, value
    return IOCType.UNKNOWN, value


def is_hash(ioc_type: IOCType) -> bool:
    return ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


def is_network(ioc_type: IOCType) -> bool:
    return ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL)
