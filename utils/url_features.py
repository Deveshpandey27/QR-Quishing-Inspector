from urllib.parse import urlparse
import ipaddress


def extract_url_features(url):
    """
    Extract security-related features from a URL.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}

    # Basic URL properties
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # HTTPS
    features["has_https"] = int(parsed.scheme.lower() == "https")

    # IP address
    try:
        ipaddress.ip_address(hostname)
        features["has_ip_address"] = 1
    except ValueError:
        features["has_ip_address"] = 0

    # Special characters
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["question_mark_count"] = url.count("?")
    features["equals_count"] = url.count("=")
    features["at_symbol"] = int("@" in url)

    # Suspicious URL characters
    features["percent_encoded"] = int("%" in url)

    # Subdomain approximation
    if features["has_ip_address"]:
     features["subdomain_count"] = 0
    else:
     features["subdomain_count"] = max(
        hostname.count(".") - 1,
        0
    )
    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "password",
        "bank",
        "payment",
        "confirm",
        "wallet",
    ]

    url_lower = url.lower()

    features["suspicious_keyword_count"] = sum(
        keyword in url_lower
        for keyword in suspicious_keywords
    )

    return features