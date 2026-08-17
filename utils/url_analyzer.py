import re
from urllib.parse import urlparse


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "security",
    "confirm",
    "confirmation",
    "update",
    "payment",
    "bank",
    "wallet",
    "free",
    "winner",
    "prize",
    "gift",
    "urgent",
    "claim",
    "reset",
]


def analyze_url(url):

    reasons = []
    risk_score = 0

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    full_url = url.lower()

    # HTTPS check
    if parsed.scheme != "https":
        risk_score += 20
        reasons.append("The URL does not use HTTPS.")

    # IP address check
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        risk_score += 25
        reasons.append("The website uses an IP address instead of a domain name.")

    # URL length
    if len(url) > 100:
        risk_score += 10
        reasons.append("The URL is unusually long.")

    if len(url) > 180:
        risk_score += 10
        reasons.append("The URL is extremely long.")

    # @ symbol
    if "@" in url:
        risk_score += 25
        reasons.append("The URL contains an @ symbol, which can hide the real destination.")

    # Too many subdomains
    if hostname.count(".") >= 3:
        risk_score += 10
        reasons.append("The domain contains many subdomains.")

    # Hyphen-heavy domain
    if hostname.count("-") >= 2:
        risk_score += 10
        reasons.append("The domain contains multiple hyphens.")

    # URL shortener
    if hostname in SHORTENER_DOMAINS:
        risk_score += 20
        reasons.append("The URL uses a URL-shortening service.")

    # Suspicious keywords
    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in full_url:
            found_words.append(word)

    if found_words:
        risk_score += min(len(found_words) * 5, 25)
        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words[:5])
        )

    # Encoded characters
    if "%" in url:
        risk_score += 10
        reasons.append("The URL contains encoded characters.")

    # Excessive query parameters
    if parsed.query.count("&") >= 4:
        risk_score += 10
        reasons.append("The URL contains many query parameters.")

    # Double slash after domain
    if "://" in url:
        remainder = url.split("://", 1)[1]

        if "//" in remainder:
            risk_score += 15
            reasons.append("The URL contains an unusual double-slash pattern.")

    # Numeric domain
    if any(char.isdigit() for char in hostname):
        risk_score += 5
        reasons.append("The domain contains numbers.")

    risk_score = min(risk_score, 100)

    return {
        "score": risk_score,
        "reasons": reasons,
        "hostname": hostname,
        "scheme": parsed.scheme,
    }