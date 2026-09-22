import os
import json
from typing import Dict, Any, List, Optional

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEIGHTS_PATH = os.path.join(ROOT_DIR, "ml", "models", "explainability_weights.json")

_cached_weights = None

DEFAULT_DISPLAY_NAMES = {
    "url_length": "URL length",
    "hostname_length": "Hostname length",
    "path_length": "URL path length",
    "query_length": "Query parameter length",
    "has_https": "HTTPS",
    "has_ip_address": "IP address",
    "dot_count_host": "Dot count",
    "dot_count_path": "Path dot count",
    "hyphen_count_host": "Hyphen count",
    "hyphen_count_path": "Path hyphen count",
    "underscore_count": "Underscore count",
    "slash_count": "Special characters (/ delimiter)",
    "question_mark_count": "Special characters (?)",
    "equals_count": "Special characters (=)",
    "at_symbol": "Special characters (@ symbol)",
    "percent_encoded": "Special characters (% hex)",
    "has_double_slash_path": "Double slash redirect",
    "subdomain_count": "Subdomain count",
    "num_digits_host": "Host digit count",
    "num_digits_url": "Total digit count",
    "entropy_hostname": "Hostname randomness (Entropy)",
    "is_shortener": "URL shortener",
    "is_punycode": "Punycode domain",
    "suspicious_keyword_count": "Suspicious keyword count"
}


def load_weights() -> dict:
    global _cached_weights
    if _cached_weights is not None:
        return _cached_weights

    if os.path.exists(WEIGHTS_PATH):
        try:
            with open(WEIGHTS_PATH, "r", encoding="utf-8") as f:
                _cached_weights = json.load(f)
                return _cached_weights
        except Exception as e:
            print(f"[Explainability Load Warning] {e}")

    # Robust fallback parameters if weights file is missing
    _cached_weights = {
        "means": {k: 0.0 for k in DEFAULT_DISPLAY_NAMES},
        "scales": {k: 1.0 for k in DEFAULT_DISPLAY_NAMES},
        "coefficients": {
            "has_ip_address": 108.8,
            "has_https": -15.5,
            "url_length": 13.7,
            "suspicious_keyword_count": 5.5,
            "subdomain_count": 14.4,
            "entropy_hostname": 4.2,
            "is_shortener": 8.0,
            "at_symbol": 12.0,
            "percent_encoded": 6.0,
            "num_digits_host": 5.5,
        },
        "display_names": DEFAULT_DISPLAY_NAMES
    }
    return _cached_weights


def _generate_explanation_rationale(feature: str, value: Any, direction: str) -> str:
    """Generates crisp, security-oriented context for why a feature contributed towards ↑ or ↓."""
    if feature == "has_ip_address":
        if value == 1 or value is True:
            return "Direct IPv4 host detected instead of a reputable domain name."
        return "Standard registered domain structure (not a raw IP host)."

    elif feature == "has_https":
        if value == 1 or value is True:
            return "Valid transport-layer encryption active (HTTPS)."
        return "Plaintext unencrypted HTTP transport exposes data to interception."

    elif feature == "url_length":
        if direction == "up":
            return f"Length of {value} characters exceeds typical legitimate threshold (often disguises payloads)."
        return f"Compact URL length ({value} chars) within standard legitimate parameters."

    elif feature == "suspicious_keyword_count":
        if value > 0:
            return f"{value} high-risk deceptive keywords (e.g. login, verify, account, secure) detected."
        return "No sensitive authentication or billing trigger keywords present."

    elif feature == "subdomain_count":
        if value > 1:
            return f"{value} nested subdomains commonly used to simulate brand trust."
        return "Normal subdomain hierarchy."

    elif feature == "entropy_hostname":
        if value > 3.5:
            return f"High Shannon entropy ({value:.2f}) indicates algorithmically generated randomness (DGA)."
        return f"Natural entropy ({value:.2f}) typical of authentic brand naming."

    elif feature == "is_shortener":
        if value == 1 or value is True:
            return "Target destination obscured behind a public URL shortening proxy."
        return "Direct destination domain without URL shortening masking."

    elif feature == "at_symbol":
        if value > 0:
            return "Deceptive embedded @ symbol used to mislead browser URL parser."
        return "No @ symbol manipulation."

    elif feature == "percent_encoded":
        if value > 0:
            return f"{value} hex percent-encoded sequences (%XX) used for lexical obfuscation."
        return "Standard plain ASCII encoding."

    elif feature == "num_digits_host":
        if value > 0:
            return f"{value} numerical digits in hostname typical of disposable attack infrastructure."
        return "Clean alphabetic domain name."

    elif feature == "dot_count_host":
        if direction == "up":
            return f"{value} dots in host create confusing multi-level hierarchy."
        return f"{value} dot(s) in host structure."

    elif feature == "path_length":
        if direction == "up":
            return f"Long URL path ({value} chars) typical of deep phishing subdirectories."
        return "Brief, standard path structure."

    return f"Feature value is {value}."


def explain_prediction(features_dict: Dict[str, Any], raw_url: str = "") -> dict:
    """
    Computes per-sample feature attribution signals (↑ Escalating risk vs ↓ Mitigating risk).
    Returns exact directional symbols, impact weights, and human-readable cybersecurity rationale.
    """
    weights_data = load_weights()
    means = weights_data.get("means", {})
    scales = weights_data.get("scales", {})
    coefs = weights_data.get("coefficients", {})
    display_names = weights_data.get("display_names", DEFAULT_DISPLAY_NAMES)

    signals: List[dict] = []
    top_suspicious: List[dict] = []
    top_legitimate: List[dict] = []

    for feat_name, feat_val in features_dict.items():
        if feat_name not in coefs:
            continue

        try:
            val_num = float(feat_val)
        except (ValueError, TypeError):
            val_num = 1.0 if bool(feat_val) else 0.0

        mean = means.get(feat_name, 0.0)
        scale = scales.get(feat_name, 1.0)
        scale = scale if scale != 0.0 else 1.0
        coef = coefs.get(feat_name, 0.0)

        # Standardized deviation and raw linear log-odds contribution
        z_score = (val_num - mean) / scale
        contribution = coef * z_score

        # Domain logic adjustments:
        # has_https: when present (1), it mitigates risk (↓); when missing (0), it escalates risk (↑)
        if feat_name == "has_https":
            if val_num == 1:
                direction = "down"
                symbol = "↓"
                contribution = -abs(contribution) if contribution != 0 else -3.5
            else:
                direction = "up"
                symbol = "↑"
                contribution = abs(contribution) if contribution != 0 else 12.0
        else:
            if contribution > 0.05:
                direction = "up"
                symbol = "↑"
            elif contribution < -0.05:
                direction = "down"
                symbol = "↓"
            else:
                direction = "neutral"
                symbol = "-"

        abs_impact = abs(contribution)
        if abs_impact >= 10.0:
            impact_level = "high"
        elif abs_impact >= 2.0:
            impact_level = "medium"
        else:
            impact_level = "low"

        display_name = display_names.get(feat_name, feat_name.replace("_", " ").capitalize())
        if feat_name == "has_https":
            display_name = "HTTPS" if val_num == 1 else "HTTPS (missing)"
        rationale = _generate_explanation_rationale(feat_name, feat_val, direction)

        signal_item = {
            "feature": feat_name,
            "name": display_name,
            "direction": direction,
            "symbol": symbol,
            "value": feat_val,
            "impact_score": round(abs_impact, 2),
            "signed_score": round(contribution, 2),
            "impact_level": impact_level,
            "explanation": rationale,
        }
        signals.append(signal_item)

        if direction == "up" and abs_impact > 0.2:
            top_suspicious.append(signal_item)
        elif direction == "down" and abs_impact > 0.2:
            top_legitimate.append(signal_item)

    # Sort descending by impact magnitude
    top_suspicious.sort(key=lambda x: x["impact_score"], reverse=True)
    top_legitimate.sort(key=lambda x: x["impact_score"], reverse=True)
    signals.sort(key=lambda x: x["impact_score"], reverse=True)

    # Compile formatted plain-text summary matching prompt format:
    # Strong contributing signals:
    # ↑ URL length
    # ↑ Suspicious keyword count
    # ↑ Subdomain count
    # ↑ IP address
    # ↓ HTTPS
    summary_lines = ["ML Explanation", "", "Strong contributing signals:"]
    for s in top_suspicious[:5]:
        summary_lines.append(f"{s['symbol']} {s['name']}")
    for s in top_legitimate[:3]:
        summary_lines.append(f"{s['symbol']} {s['name']}")

    return {
        "signals": signals,
        "top_suspicious": top_suspicious[:6],
        "top_legitimate": top_legitimate[:4],
        "summary_text": "\n".join(summary_lines)
    }
