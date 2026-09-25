import ipaddress
import re
from urllib.parse import urlparse

MAX_TEXT_LENGTH = 200_000
UNUSUAL_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "country", "review"}

def validate_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include an http or https scheme and a hostname")
    return value

def parse_ip_or_hostname(value: str) -> tuple[str, str | None]:
    value = value.strip()
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9._-]+", value) or "." not in value:
        raise ValueError("Enter a valid IPv4, IPv6, or hostname")
    return "domain", value.lower().rstrip(".")
