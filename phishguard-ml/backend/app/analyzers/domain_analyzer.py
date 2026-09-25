import ipaddress
import re
from datetime import datetime, timezone
from app.schemas import AnalysisResult, Finding
from app.utils.url_features import UNUSUAL_TLDS

def analyze_domain(value: str, input_type: str = "domain") -> AnalysisResult:
    value = value.strip().lower().rstrip(".")
    findings: list[Finding] = []
    try:
        address = ipaddress.ip_address(value)
        is_private = address.is_private or address.is_loopback or address.is_reserved
        features = {"is_ip": True, "version": address.version, "is_private_or_local": is_private, "is_punycode": False, "subdomain_depth": 0, "hostname_length": len(value), "suspicious_characters": False}
        if is_private: findings.append(Finding(severity="medium", title="Private or local address", description="This address belongs to a private, loopback, or reserved range."))
    except ValueError:
        labels = value.split(".")
        tld = labels[-1] if labels else ""
        malformed = len(value) > 253 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels) or not re.fullmatch(r"[a-z0-9.-]+", value)
        features = {"is_ip": False, "is_punycode": "xn--" in value, "subdomain_depth": max(0, len(labels) - 2), "hostname_length": len(value), "suspicious_characters": bool(re.search(r"[^a-z0-9.-]", value)), "numeric_hostname": value.replace(".", "").isdigit(), "unusual_tld": tld in UNUSUAL_TLDS, "malformed": malformed}
        if malformed: findings.append(Finding(severity="high", title="Malformed hostname", description="The value does not follow ordinary hostname syntax."))
        if features["is_punycode"] or features["unusual_tld"]: findings.append(Finding(severity="medium", title="Domain requires additional scrutiny", description="The domain uses punycode or an unusual TLD; inspect the registrant through a trusted source."))
    if not findings: findings.append(Finding(severity="low", title="No major local indicators", description="No significant indicators were detected without contacting the host."))
    severity = max((finding.severity for finding in findings), key=lambda item: {"low": 0, "medium": 1, "high": 2}[item])
    probability = {"low": 0.12, "medium": 0.52, "high": 0.82}[severity]
    return AnalysisResult(risk_level=severity, probability=probability, category="network", model="domain_static_rules_v1", findings=findings, features=features, recommendations=["Use trusted WHOIS, DNS, or security tooling separately if enrichment is required.", "Do not scan or connect to an untrusted host from this analyzer."], timestamp=datetime.now(timezone.utc).isoformat(), input_type=input_type, input_label=value)
