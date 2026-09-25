import sys
sys.path.insert(0, 'backend')
from app.analyzers.email_analyzer import analyze_email

def test_reply_to_mismatch():
    result = analyze_email('Urgent verify', 'Please login at https://example.test', 'alerts@bank.test', 'help@random.test')
    assert result.features['domain_mismatch'] is True
    assert result.risk_level == 'high'

def test_eml_attachment_is_not_opened():
    raw = b'Subject: Hello\nFrom: a@example.com\n\nPlain body'
    result = analyze_email('', '', eml_bytes=raw)
    assert result.features['attachment_count'] == 0
