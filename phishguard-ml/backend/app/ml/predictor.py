from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length", "fragment_length", "dot_count", "hyphen_count", "underscore_count", "digit_count", "subdomain_count", "query_parameter_count", "special_character_count", "has_at_symbol", "is_ip_hostname", "uses_https", "suspicious_keyword_count", "hostname_entropy", "path_entropy", "numeric_character_percentage", "redirect_count", "has_punycode", "unusual_tld",
]
MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "url_model.joblib"

def predict_url(features: dict) -> tuple[float, str]:
    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        vector = [[float(features.get(name, 0)) for name in FEATURE_NAMES]]
        return float(model.predict_proba(vector)[0][1]), "url_random_forest_v1"
    score = 0.04
    score += min(float(features["suspicious_keyword_count"]) * 0.06, 0.24)
    score += 0.18 if features["is_ip_hostname"] else 0
    score += 0.12 if features["has_at_symbol"] else 0
    score += 0.10 if features["has_punycode"] else 0
    score += 0.08 if features["unusual_tld"] else 0
    score += min(float(features["subdomain_count"]) * 0.025, 0.12)
    score += 0.08 if features["numeric_character_percentage"] > 20 else 0
    return min(score, 0.97), "heuristic_baseline_v1"

def risk_level(probability: float) -> str:
    if probability >= 0.70: return "high"
    if probability >= 0.38: return "medium"
    return "low"
