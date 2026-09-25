import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlparse

SUSPICIOUS_KEYWORDS = ("login", "verify", "verification", "secure", "account", "update", "password", "wallet", "signin", "authenticate", "confirm", "billing")
UNUSUAL_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "country", "review"}

def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)

def extract_url_features(url: str) -> dict[str, float | int | bool]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    host_parts = hostname.split(".") if hostname else []
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    full_lower = url.lower()
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    special_count = len(re.findall(r"[^A-Za-z0-9]", url))
    digits = sum(char.isdigit() for char in url)
    tld = host_parts[-1].lower() if host_parts and not is_ip else ""
    return {
        "url_length": len(url), "hostname_length": len(hostname), "path_length": len(parsed.path), "query_length": len(parsed.query),
        "fragment_length": len(parsed.fragment), "dot_count": url.count("."), "hyphen_count": url.count("-"), "underscore_count": url.count("_"),
        "digit_count": digits, "subdomain_count": max(0, len(host_parts) - 2) if not is_ip else 0, "query_parameter_count": len(query_params),
        "special_character_count": special_count, "has_at_symbol": "@" in url, "is_ip_hostname": is_ip, "uses_https": parsed.scheme.lower() == "https",
        "suspicious_keyword_count": sum(keyword in full_lower for keyword in SUSPICIOUS_KEYWORDS), "hostname_entropy": entropy(hostname), "path_entropy": entropy(parsed.path),
        "numeric_character_percentage": round((digits / len(url)) * 100, 4) if url else 0.0, "redirect_count": 0,
        "has_punycode": "xn--" in hostname.lower(), "unusual_tld": tld in UNUSUAL_TLDS,
    }
