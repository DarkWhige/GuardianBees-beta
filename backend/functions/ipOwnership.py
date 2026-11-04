"""Best-effort cached ownership lookup for public IP addresses."""

import ipaddress
import json
import threading
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


_cache = {}
_lock = threading.Lock()


def lookup(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid IP address"

    if address.is_private or address.is_loopback or address.is_reserved:
        return "Private/local network"

    with _lock:
        if ip in _cache:
            return _cache[ip]

    owner = "Unknown organization"
    request = Request(
        f"https://rdap.org/ip/{ip}",
        headers={"Accept": "application/rdap+json", "User-Agent": "GuardianBees/1.0"},
    )
    try:
        with urlopen(request, timeout=4) as response:
            body = json.loads(response.read().decode("utf-8"))
        owner = _owner_from_rdap(body) or owner
    except (HTTPError, URLError, TimeoutError, ValueError, TypeError, OSError):
        pass

    with _lock:
        _cache[ip] = owner
    return owner


def _owner_from_rdap(body):
    for key in ("name", "orgName", "handle"):
        if body.get(key):
            return str(body[key])

    for entity in body.get("entities", []):
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2:
            continue
        for value in vcard[1]:
            if len(value) >= 4 and value[0] in {"fn", "org"} and value[3]:
                return str(value[3])
    return None
