import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from urllib.parse import urlparse
from app.schemas import AnalysisResult, Finding

URGENCY = ("urgent", "immediately", "within 24 hours", "act now", "suspended")
FINANCIAL = ("payment", "invoice", "bank", "transfer", "gift card", "bitcoin", "wallet")
CREDENTIALS = ("password", "login", "verify", "verification", "sign in", "authenticate")

def _domain(address: str) -> str:
    return parseaddr(address)[1].split("@", 1)[-1].lower() if "@" in parseaddr(address)[1] else ""

def _body(message) -> tuple[str, str]:
    plain, html = [], []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_maintype() == "multipart": continue
        if part.get_filename(): continue
        content = part.get_content_type()
        try: text = part.get_content()
        except Exception: text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace") if part.get_payload(decode=True) else ""
        (html if content == "text/html" else plain).append(text)
    return "\n".join(plain), "\n".join(html)

def analyze_email(subject: str, body: str, sender: str = "", reply_to: str = "", eml_bytes: bytes | None = None) -> AnalysisResult:
    if eml_bytes is not None:
        message = BytesParser(policy=policy.default).parsebytes(eml_bytes)
        subject, sender, reply_to = message.get("subject", ""), message.get("from", ""), message.get("reply-to", "")
        plain_body, html_body = _body(message)
        body = plain_body or html_body
        attachments = [part.get_filename() for part in message.walk() if part.get_filename()]
        return _build_result(subject, body, sender, reply_to, html_body, attachments)
    message = Parser(policy=policy.default).parsestr(f"Subject: {subject}\nFrom: {sender}\nReply-To: {reply_to}\n\n{body}")
    _, html_body = _body(message)
    return _build_result(subject, body, sender, reply_to, html_body, [])

def _build_result(subject: str, body: str, sender: str, reply_to: str, html_body: str, attachments: list[str | None]) -> AnalysisResult:
    combined = f"{subject} {body}".lower()
    urls = re.findall(r"https?://[^\s<>\"']+", body + " " + html_body)
    sender_domain, reply_domain = _domain(sender), _domain(reply_to)
    mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)
    features = {"from": sender, "reply_to": reply_to, "return_path": "", "sender_domain": sender_domain, "reply_to_domain": reply_domain, "domain_mismatch": mismatch, "url_count": len(urls), "urls": urls, "attachment_count": len(attachments), "attachment_filenames": attachments, "credential_language": sum(term in combined for term in CREDENTIALS), "urgency_indicators": sum(term in combined for term in URGENCY), "financial_language": sum(term in combined for term in FINANCIAL), "suspicious_link_indicators": sum("@" in url or "xn--" in url for url in urls), "has_html": bool(html_body), "hidden_element_indicators": len(re.findall(r"display\s*:\s*none|visibility\s*:\s*hidden", html_body, re.I))}
    findings: list[Finding] = []
    if mismatch: findings.append(Finding(severity="high", title="From and Reply-To domains differ", description="Replies may be routed to a different domain than the visible sender."))
    if features["credential_language"] and features["url_count"]: findings.append(Finding(severity="high", title="Credential request with links", description="The message combines credential-related language with one or more links."))
    if features["urgency_indicators"] or features["financial_language"]: findings.append(Finding(severity="medium", title="Urgency or financial pressure", description="The message uses pressure or financial terms that deserve independent verification."))
    if attachments: findings.append(Finding(severity="medium", title="Attachment present", description="Attachment names were recorded, but attachments were not opened or executed."))
    if not findings: findings.append(Finding(severity="low", title="No major email indicators", description="No significant phishing indicators were detected by the static parser."))
    highest = max((item.severity for item in findings), key=lambda item: {"low": 0, "medium": 1, "high": 2}[item])
    probability = {"low": 0.14, "medium": 0.55, "high": 0.86}[highest]
    return AnalysisResult(risk_level=highest, probability=probability, category="phishing", model="email_static_rules_v1", findings=findings, features=features, recommendations=["Verify the sender using a trusted channel.", "Do not open attachments or follow links from an unexpected message."], timestamp=datetime.now(timezone.utc).isoformat(), input_type="eml" if attachments else "email", input_label=subject or "Untitled email")
