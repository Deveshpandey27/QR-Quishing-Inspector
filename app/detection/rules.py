import re
from urllib.parse import unquote
from app.detection.normalizer import normalize_url
from app.detection.reputation import TRUSTED_DOMAINS, HIGH_TARGET_BRANDS


# Canonical security/urgency keywords mapped to clean display names
KEYWORD_MAPPING = {
    "login": "Login keyword",
    "signin": "Signin keyword",
    "verify": "Verify keyword",
    "verification": "Verify keyword",
    "account": "Account keyword",
    "update": "Update keyword",
    "password": "Password keyword",
    "passcode": "Password keyword",
    "credential": "Credential keyword",
    "banking": "Banking keyword",
    "security": "Security keyword",
    "confirm": "Confirm keyword",
    "confirmation": "Confirm keyword",
    "wallet": "Wallet keyword",
    "authenticate": "Authentication keyword",
    "validation": "Validation keyword",
    "billing": "Billing keyword",
    "support": "Support keyword",
    "recover": "Recovery keyword",
    "oauth": "OAuth keyword",
}

# Abuse-prone / disposable phishing TLDs
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "fit", "gq", "cf", "tk", "ml", "ga",
    "zip", "mov", "surfer", "buzz", "racing", "download", "stream", "party",
    "trade", "science", "country", "kim", "cricket", "monster", "quest", "rest",
    "cam", "live", "link", "tokyo", "club", "vip", "icu", "bar",
}

# Dangerous / executable file extensions
DANGEROUS_EXTENSIONS = (
    ".exe", ".apk", ".bat", ".sh", ".vbs", ".scr", ".iso", ".dmg", ".zip",
    ".msi", ".cmd", ".jar", ".ps1", ".hta", ".reg"
)

# Sensitive target / traversal paths
SENSITIVE_PATHS = (
    "/wp-login", "/wp-admin", "/.env", "/.git", "/config", "/cmd", "/shell",
    "/cgi-bin", "/admin/login", "/phpmyadmin"
)

# Query parameters commonly used for open redirect or credential interception
SUSPICIOUS_QUERY_KEYS = {
    "redirect", "url", "next", "dest", "destination", "target", "forward", "link",
    "token", "user", "email", "password", "pass", "auth", "otp", "pin", "credential"
}


def _matches_keyword(text: str, keyword: str) -> bool:
    """
    Match keyword using delimiter boundaries (slash, dot, hyphen, underscore, etc.)
    Prevents false positives like matching 'bank' in 'southbank' or 'riverbank'.
    """
    pattern = rf"(?:^|[^a-zA-Z0-9]){re.escape(keyword)}(?:$|[^a-zA-Z0-9])"
    return bool(re.search(pattern, text, re.IGNORECASE))


def analyze_url_security(raw_url: str) -> dict:
    """
    Perform comprehensive explainable cybersecurity inspection across 13 URL characteristics:
    1. HTTPS missing (HTTP instead of HTTPS)
    2. IP address instead of domain
    3. Unusually long URL
    4. Excessive subdomains
    5. Suspicious keywords (itemized: Login, Verify, Account, etc.)
    6. Excessive hyphens
    7. @ symbol in URL (userinfo evasion)
    8. Percent encoding
    9. Suspicious TLD
    10. URL shortener
    11. Unusual network port
    12. Suspicious path pattern / executable target
    13. Suspicious query parameters

    Returns:
        dict with score (0-100), risk_level, reasons, indicators, detected, and metadata.
    """
    norm = normalize_url(raw_url)
    if not norm["valid"]:
        return {
            "score": 85,
            "risk_level": "HIGH RISK",
            "reasons": [norm.get("error", "Invalid or malformed URL.")],
            "indicators": [{"name": "malformed_url", "severity": "high", "weight": 85}],
            "detected": ["Malformed or invalid URL"],
            "hostname": "",
            "registered_domain": "",
            "is_trusted": False,
            "scheme": "",
            "normalized_url": raw_url,
        }

    hostname = norm["hostname"]
    registered_domain = norm["registered_domain"]
    subdomains = norm["subdomains"]
    path = norm["path"]
    query = norm["query"]
    scheme = norm["scheme"]
    port = norm.get("port")
    tld = norm.get("tld", "")
    full_url = norm["url"]

    score = 0
    reasons = []
    indicators = []
    detected = []

    is_trusted = registered_domain in TRUSTED_DOMAINS

    # -------------------------------------------------
    # 1. Transport Security (HTTPS Missing)
    # -------------------------------------------------
    if scheme != "https":
        score += 15
        detected.append("HTTP instead of HTTPS")
        indicators.append({
            "name": "missing_https",
            "severity": "medium",
            "weight": 15,
            "detail": f"Protocol is '{scheme}', not https."
        })
        reasons.append(
            "The URL does not use encrypted HTTPS, leaving traffic vulnerable to interception."
        )

    # -------------------------------------------------
    # 2. IP Address Hostname
    # -------------------------------------------------
    if norm["is_ip"]:
        score += 35
        detected.append("IP address detected")
        indicators.append({
            "name": "ip_host",
            "severity": "high",
            "weight": 35,
            "detail": f"Hostname '{hostname}' is an IP address."
        })
        reasons.append(
            "The website uses an IP address instead of a registered domain name, "
            "bypassing standard domain reputation and security verification."
        )

    # -------------------------------------------------
    # 3. URL Shortener Detection (Crucial for Quishing)
    # -------------------------------------------------
    if norm["is_shortener"]:
        score += 25
        detected.append("URL shortener")
        indicators.append({
            "name": "url_shortener",
            "severity": "medium",
            "weight": 25,
            "detail": f"Domain '{hostname}' is a known URL shortener."
        })
        reasons.append(
            "⚠ URL SHORTENER DETECTED: The QR code points to a shortened URL. "
            "Destination cannot be trusted based only on the visible short URL."
        )

    # -------------------------------------------------
    # 4. Punycode / IDN Homograph Detection
    # -------------------------------------------------
    if norm["is_punycode"]:
        score += 30
        detected.append("Punycode (IDN homograph)")
        indicators.append({
            "name": "punycode_homograph",
            "severity": "high",
            "weight": 30,
            "detail": f"Hostname '{hostname}' uses Punycode encoding."
        })
        reasons.append(
            "The domain uses Punycode (IDN homograph) characters ('xn--'), "
            "which can visually mimic legitimate brand domains using lookalike alphabets."
        )

    # -------------------------------------------------
    # 5. Embedded Credentials / @ Symbol Evasion
    # -------------------------------------------------
    if norm["has_auth"] or "@" in raw_url:
        score += 30
        detected.append("@ symbol in URL")
        indicators.append({
            "name": "embedded_credentials_at_symbol",
            "severity": "high",
            "weight": 30,
            "detail": "Contains '@' symbol in authority section."
        })
        reasons.append(
            "The URL contains an '@' symbol, which can trick users by showing a safe "
            "brand name before the '@' while redirecting to an entirely different server."
        )

    # -------------------------------------------------
    # 6. Brand Impersonation Detection
    # -------------------------------------------------
    if not is_trusted and not norm["is_shortener"]:
        host_parts = hostname.split(".")
        for brand_key, brand_display in HIGH_TARGET_BRANDS.items():
            brand_in_host = False
            for part in host_parts:
                if brand_key in part:
                    brand_in_host = True
                    break

            if brand_in_host:
                score += 35
                detected.append(f"Brand impersonation ({brand_display})")
                indicators.append({
                    "name": "brand_impersonation",
                    "severity": "high",
                    "weight": 35,
                    "detail": f"Host mimics '{brand_display}' but resolves to '{registered_domain}'."
                })
                reasons.append(
                    f"Possible brand impersonation: the domain references '{brand_display}' "
                    f"but is hosted on '{registered_domain}'."
                )
                break

    # -------------------------------------------------
    # 7. Context-Aware Keyword Matching (Itemized)
    # -------------------------------------------------
    if not is_trusted:
        decoded_path_query = unquote(f"{path}?{query}")
        matched_canonical = set()

        for kw_token, canonical_title in KEYWORD_MAPPING.items():
            if _matches_keyword(hostname, kw_token) or _matches_keyword(decoded_path_query, kw_token):
                matched_canonical.add(canonical_title)

        for kw_title in sorted(matched_canonical):
            score += 12
            detected.append(kw_title)
            kw_slug = kw_title.lower().replace(" ", "_")
            indicators.append({
                "name": kw_slug,
                "severity": "medium",
                "weight": 12,
                "detail": f"Credential/urgency keyword: {kw_title}"
            })
            reasons.append(
                f"Credential harvesting or urgency indicator: '{kw_title}'."
            )

    # -------------------------------------------------
    # 8. Excessive Subdomains
    # -------------------------------------------------
    if len(subdomains) >= 3 and not is_trusted:
        score += 15
        detected.append("Excessive subdomains")
        indicators.append({
            "name": "excessive_subdomains",
            "severity": "medium",
            "weight": 15,
            "detail": f"{len(subdomains)} subdomain levels."
        })
        reasons.append(
            f"The domain contains an unusually deep subdomain structure ({len(subdomains)} levels), "
            "often seen in disposable phishing infrastructure."
        )

    # -------------------------------------------------
    # 9. Excessive Hyphens
    # -------------------------------------------------
    hyphen_count = hostname.count("-")
    if (hyphen_count >= 2 or raw_url.count("-") >= 4) and not is_trusted:
        score += 10
        detected.append("Excessive hyphens")
        indicators.append({
            "name": "excessive_hyphens",
            "severity": "low",
            "weight": 10,
            "detail": f"{hyphen_count} hyphens in hostname."
        })
        reasons.append(
            f"The hostname contains {hyphen_count} hyphens, a common pattern in synthesized phishing domains."
        )

    # -------------------------------------------------
    # 10. Unusually Long URL
    # -------------------------------------------------
    url_len = len(full_url)
    if (url_len > 80 and not is_trusted) or url_len > 150:
        score += 10
        detected.append("Unusually long URL")
        indicators.append({
            "name": "unusually_long_url",
            "severity": "low",
            "weight": 10,
            "detail": f"Length: {url_len} chars."
        })
        reasons.append(f"The URL is unusually long ({url_len} characters), which can obscure malicious destinations.")

    # -------------------------------------------------
    # 11. Percent Encoding in URL
    # -------------------------------------------------
    if "%" in raw_url:
        score += 15
        detected.append("Percent encoding")
        indicators.append({
            "name": "percent_encoding",
            "severity": "medium",
            "weight": 15,
            "detail": f"Contains {raw_url.count('%')} percent-encoded characters."
        })
        reasons.append("The domain or URL contains percent-encoded characters used to obscure its true identity.")

    # -------------------------------------------------
    # 12. Suspicious Top-Level Domain (TLD)
    # -------------------------------------------------
    if tld and tld in SUSPICIOUS_TLDS and not is_trusted:
        score += 20
        detected.append(f"Suspicious TLD (.{tld})")
        indicators.append({
            "name": "suspicious_tld",
            "severity": "medium",
            "weight": 20,
            "detail": f"TLD '.{tld}' is associated with high phishing abuse."
        })
        reasons.append(f"The domain uses the '.{tld}' top-level domain, which has a statistically high rate of phishing abuse.")

    # -------------------------------------------------
    # 13. Unusual Network Port
    # -------------------------------------------------
    if port is not None and port not in (80, 443):
        score += 25
        detected.append(f"Unusual port (:{port})")
        indicators.append({
            "name": "unusual_port",
            "severity": "high",
            "weight": 25,
            "detail": f"Explicit non-standard port :{port}."
        })
        reasons.append(f"The URL specifies a non-standard network port (:{port}), bypassing standard web traffic controls.")

    # -------------------------------------------------
    # 14. Suspicious Path Pattern / Executable
    # -------------------------------------------------
    path_lower = path.lower()
    has_exec_ext = any(path_lower.endswith(ext) or f"{ext}?" in full_url.lower() for ext in DANGEROUS_EXTENSIONS)
    has_sensitive_path = any(sp in path_lower for sp in SENSITIVE_PATHS)
    has_traversal = "//" in path or "../" in path or "..\\" in path

    if (has_exec_ext or has_sensitive_path or has_traversal) and not is_trusted:
        score += 25
        detected.append("Suspicious path")
        indicators.append({
            "name": "suspicious_path",
            "severity": "high",
            "weight": 25,
            "detail": f"Path matches suspicious pattern or extension: {path}"
        })
        if has_traversal:
            indicators.append({
                "name": "double_slash_evasion",
                "severity": "medium",
                "weight": 15,
                "detail": "Path contains double slashes or traversal."
            })
        reasons.append("The URL path contains references to executable files, sensitive administrative panels, or directory traversal evasion.")

    # -------------------------------------------------
    # 15. Suspicious Query Parameters
    # -------------------------------------------------
    if query and not is_trusted:
        query_lower = query.lower()
        has_suspicious_query = any(f"{qk}=" in query_lower for qk in SUSPICIOUS_QUERY_KEYS)
        if has_suspicious_query:
            score += 20
            detected.append("Suspicious query parameters")
            indicators.append({
                "name": "suspicious_query_params",
                "severity": "medium",
                "weight": 20,
                "detail": "Query string contains redirect or credential capture parameters."
            })
            reasons.append("The URL query string contains parameters indicative of credential capture or open-redirect evasion.")

    # -------------------------------------------------
    # Safe Domain Confirmation
    # -------------------------------------------------
    if is_trusted and score == 0:
        reasons.append(
            f"Verified reputable domain ({registered_domain}). No suspicious indicators detected."
        )

    # Cap score
    score = min(max(score, 0), 100)

    # Classification
    if score >= 70:
        risk_level = "HIGH RISK"
    elif score >= 35:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOW RISK"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "indicators": indicators,
        "detected": detected,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "scheme": scheme,
        "port": port,
        "is_trusted": is_trusted,
        "is_shortener": norm["is_shortener"],
        "is_ip": norm["is_ip"],
        "normalized_url": full_url,
    }
