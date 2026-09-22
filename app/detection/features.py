import math
from collections import Counter
from urllib.parse import urlparse
from app.detection.normalizer import normalize_url


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "password",
    "passcode",
    "credential",
    "banking",
    "security",
    "confirm",
    "confirmation",
    "wallet",
    "authenticate",
    "validation",
]


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy often correlates with randomly generated (DGA) or obfuscated domain names.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_url_features(url: str) -> dict:
    """
    Extract robust, invariant cybersecurity features from a URL.
    Canonicalizes 'www.' across both hostname and URL string to eliminate
    the dataset shortcut bias where benign sites overfit on 'www' prefixing.
    """
    norm = normalize_url(url)
    raw_url = norm["url"] if norm["valid"] else (url or "")
    raw_hostname = norm["hostname"] if norm["valid"] else ""
    path = norm["path"] if norm["valid"] else ""
    query = norm["query"] if norm["valid"] else ""
    scheme = norm["scheme"] if norm["valid"] else ""

    # Canonicalize both hostname and URL to strip 'www.' alias
    if raw_hostname.startswith("www."):
        hostname = raw_hostname[4:]
        clean_url = raw_url.replace("://www.", "://", 1)
    else:
        hostname = raw_hostname
        clean_url = raw_url

    features = {}

    # 1. Structural lengths
    features["url_length"] = len(clean_url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # 2. Security protocols & IP
    features["has_https"] = int(scheme == "https")
    features["has_ip_address"] = int(norm["is_ip"] if norm["valid"] else 0)

    # 3. Delimiters and special characters
    features["dot_count_host"] = hostname.count(".")
    features["dot_count_path"] = path.count(".")
    features["hyphen_count_host"] = hostname.count("-")
    features["hyphen_count_path"] = path.count("-")
    features["underscore_count"] = clean_url.count("_")
    features["slash_count"] = path.count("/")
    features["question_mark_count"] = clean_url.count("?")
    features["equals_count"] = clean_url.count("=")
    features["at_symbol"] = int("@" in clean_url)
    features["percent_encoded"] = int("%" in clean_url)
    features["has_double_slash_path"] = int("//" in path)

    # 4. Domain & subdomain structure (excluding 'www' alias)
    real_subdomains = [s for s in norm.get("subdomains", []) if s.lower() != "www"]
    features["subdomain_count"] = len(real_subdomains)

    # 5. Digit counts and character entropy
    features["num_digits_host"] = sum(c.isdigit() for c in hostname)
    features["num_digits_url"] = sum(c.isdigit() for c in clean_url)
    features["entropy_hostname"] = calculate_entropy(hostname)

    # 6. Quishing / Phishing specific flags
    features["is_shortener"] = int(norm.get("is_shortener", False))
    features["is_punycode"] = int(norm.get("is_punycode", False))

    # 7. Suspicious keyword presence
    url_lower = clean_url.lower()
    features["suspicious_keyword_count"] = sum(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)

    return features