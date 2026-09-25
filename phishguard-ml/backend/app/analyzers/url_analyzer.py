from datetime import datetime, timezone
from urllib.parse import urlparse
from app.ml.predictor import predict_url, risk_level
from app.schemas import AnalysisResult, Finding
from app.utils.url_features import extract_url_features
from app.utils.validators import validate_url

def analyze_url(value: str) -> AnalysisResult:
    url = validate_url(value)
    features = extract_url_features(url)
    probability, model = predict_url(features)
    findings: list[Finding] = []
    if features["suspicious_keyword_count"] >= 2:
        findings.append(Finding(severity="medium", title="Phishing language in URL", description="The URL contains several account or verification terms often seen in deceptive links."))
    if features["is_ip_hostname"] or features["has_at_symbol"] or features["has_punycode"]:
        findings.append(Finding(severity="high", title="Suspicious URL structure", description="The hostname or URL syntax contains structural indicators that warrant independent verification."))
    if features["unusual_tld"]:
        findings.append(Finding(severity="medium", title="Unusual top-level domain", description="The domain uses a TLD that is less common in ordinary service links."))
    if not findings:
        findings.append(Finding(severity="low", title="No major URL indicators", description="No significant phishing indicators were detected by the available static checks."))
    return AnalysisResult(risk_level=risk_level(probability), probability=round(probability, 4), category="phishing", model=model, findings=findings, features=features, recommendations=["Verify the destination through an independent trusted channel.", "Do not enter credentials until the organization confirms the link."], timestamp=datetime.now(timezone.utc).isoformat(), input_type="url", input_label=urlparse(url).hostname or url)
