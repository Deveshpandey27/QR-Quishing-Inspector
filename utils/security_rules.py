from urllib.parse import urlparse
from utils.url_features import extract_url_features

def analyze_url_security(url):
    """
    Analyze a URL using explainable security rules.

    Returns:
        {
            "score": int,
            "risk_level": str,
            "reasons": list
        }
    """

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    score = 0
    reasons = []

    # -------------------------------------------------
    # Rule 1: Missing HTTPS
    # -------------------------------------------------

    if parsed.scheme.lower() != "https":
        score += 10
        reasons.append(
            "The URL does not use HTTPS."
        )

    # -------------------------------------------------
    # Rule 2: IP address instead of domain
    # -------------------------------------------------

    features = extract_url_features(url)
    if features["has_ip_address"]:
        score += 25
        reasons.append(
             "The URL uses an IP address instead of a domain name."
        )

    # -------------------------------------------------
    # Rule 3: Suspicious keywords
    # -------------------------------------------------

    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "password",
        "bank",
        "payment",
        "wallet",
        "confirm",
        "security",
    ]

    matched_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url.lower()
    ]

    if matched_keywords:
        score += min(len(matched_keywords) * 5, 15)

        reasons.append(
            "Suspicious security-related keywords detected: "
            + ", ".join(matched_keywords)
        )

    # -------------------------------------------------
    # Rule 4: @ symbol
    # -------------------------------------------------

    if "@" in url:
        score += 20

        reasons.append(
            "The URL contains an @ symbol, which can be "
            "used to obscure the actual destination."
        )

    # -------------------------------------------------
    # Rule 5: Very long URL
    # -------------------------------------------------

    if len(url) > 100:
        score += 10

        reasons.append(
            "The URL is unusually long."
        )

    # -------------------------------------------------
    # Rule 6: Excessive subdomains
    # -------------------------------------------------

    if hostname.count(".") >= 4:
        score += 10

        reasons.append(
            "The hostname contains an unusually high "
            "number of domain levels."
        )

    # -------------------------------------------------
    # Rule 7: Percent encoding
    # -------------------------------------------------

    if "%" in url:
        score += 5

        reasons.append(
            "The URL contains percent-encoded characters."
        )

    # -------------------------------------------------
    # Limit score
    # -------------------------------------------------

    score = min(score, 100)

    # -------------------------------------------------
    # Risk classification
    # -------------------------------------------------

    if score >= 70:
        risk_level = "HIGH RISK"

    elif score >= 40:
        risk_level = "SUSPICIOUS"

    else:
        risk_level = "LOW RISK"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
    }