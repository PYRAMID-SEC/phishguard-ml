from datetime import datetime, timezone
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.schemas import AnalysisResult, Finding

def analyze_html(html: str) -> AnalysisResult:
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    actions = [form.get("action", "") for form in forms]
    anchors = [anchor.get("href", "") for anchor in soup.find_all("a")]
    scripts = soup.find_all("script")
    external_scripts = [script.get("src", "") for script in scripts if script.get("src", "").startswith(("http://", "https://"))]
    external_domains = set()
    for link in anchors + external_scripts + actions:
        host = urlparse(link).hostname
        if host: external_domains.add(host)
    password_fields = soup.find_all("input", attrs={"type": lambda value: value and value.lower() == "password"})
    text_fields = soup.find_all("input", attrs={"type": lambda value: value and value.lower() in {"text", "email"}})
    hidden_fields = soup.find_all("input", attrs={"type": lambda value: value and value.lower() == "hidden"})
    login_terms = sum(term in soup.get_text(" ", strip=True).lower() for term in ("login", "sign in", "password", "verify", "account"))
    features = {"form_count": len(forms), "password_input_count": len(password_fields), "text_input_count": len(text_fields), "hidden_input_count": len(hidden_fields), "iframe_count": len(soup.find_all("iframe")), "script_count": len(scripts), "external_script_count": len(external_scripts), "external_domain_count": len(external_domains), "form_actions": actions, "external_form_submissions": sum(bool(urlparse(action).hostname) for action in actions), "login_keyword_count": login_terms, "credential_collection": bool(password_fields), "suspicious_iframe_count": sum(bool(urlparse(frame.get("src", "")).hostname) for frame in soup.find_all("iframe")), "anchor_count": len(anchors), "external_anchor_count": sum(bool(urlparse(anchor).hostname) for anchor in anchors), "title": soup.title.get_text(strip=True) if soup.title else "", "meta_count": len(soup.find_all("meta")), "inline_javascript": any(script.get("src") is None and script.get_text(strip=True) for script in scripts)}
    findings: list[Finding] = []
    external_actions = [action for action in actions if urlparse(action).hostname]
    if password_fields and external_actions: findings.append(Finding(severity="high", title="Credential collection form", description="The HTML contains a password field and a form action with a hostname; verify the destination before entering credentials."))
    elif password_fields: findings.append(Finding(severity="medium", title="Password input detected", description="The static HTML contains a password input. This is not proof of malicious behavior, but it warrants context."))
    if login_terms >= 2 or len(soup.find_all("iframe")) > 1: findings.append(Finding(severity="medium", title="Multiple login-related indicators", description="The page contains several terms or embedded elements associated with account workflows."))
    if not findings: findings.append(Finding(severity="low", title="No significant static indicators", description="No significant phishing indicators were detected by the static analyzer."))
    highest = max((item.severity for item in findings), key=lambda item: {"low": 0, "medium": 1, "high": 2}[item])
    probability = {"low": 0.10, "medium": 0.50, "high": 0.84}[highest]
    return AnalysisResult(risk_level=highest, probability=probability, category="phishing", model="html_static_rules_v1", findings=findings, features=features, recommendations=["Never render or execute untrusted HTML in a browser session.", "Verify forms and destinations through an independent trusted channel."], timestamp=datetime.now(timezone.utc).isoformat(), input_type="html", input_label=features["title"] or "Pasted HTML")
