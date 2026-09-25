import sys
sys.path.insert(0, 'backend')
from app.analyzers.url_analyzer import analyze_url
from app.utils.url_features import extract_url_features

def test_url_features_capture_structure():
    features = extract_url_features('https://login.example.com/verify?id=123')
    assert features['uses_https'] is True
    assert features['subdomain_count'] == 1
    assert features['query_parameter_count'] == 1
    assert features['suspicious_keyword_count'] >= 2

def test_legitimate_url_is_not_automatically_high():
    assert analyze_url('https://www.example.com/about').risk_level == 'low'

def test_suspicious_url_has_findings():
    result = analyze_url('http://192.0.2.10/login/verify?account=1')
    assert result.findings
    assert result.features['is_ip_hostname'] is True
