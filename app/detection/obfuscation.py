"""
Section 13: Anti-Obfuscation Detection Engine.
Identifies advanced evasion techniques:
1. URL Encoding & Double Encoding
2. Unicode & Punycode (IDN Homograph) Domains
3. Hexadecimal, DWORD, and Alternative IP Representations
4. Multiple Redirect Chains (Redirect Bouncing)
5. Nested URLs (Embedded Parameter Concealment)
"""

import re
import socket
import ipaddress
import urllib.parse
import time
import httpx
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("obfuscation_detector")

# Cache for redirect chain inspections to prevent redundant network queries
_REDIRECT_CHAIN_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL = 3600

# Canonical Homoglyph / Confusable Mapping (Cyrillic, Greek, Latin Lookalikes)
HOMOGLYPH_MAP = {
    # Cyrillic small lookalikes
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "о": "o",
    "р": "p", "ѕ": "s", "х": "x", "у": "y", "в": "b", "п": "n",
    "т": "t", "г": "r", "м": "m", "к": "k",
    # Cyrillic capital lookalikes
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I",
    "Ј": "J", "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T",
    "Х": "X", "Ү": "Y",
    # Greek lookalikes
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
}

# Suspicious query parameter keys frequently targeted for open redirect or nested payloads
NESTED_URL_PARAM_KEYS = {
    "url", "dest", "destination", "redirect", "redirect_url", "redirect_uri",
    "target", "link", "forward", "forward_url", "next", "return", "return_url",
    "goto", "r", "u", "uri", "site", "to", "out", "view", "jump"
}


def check_unicode_punycode(url: str, hostname: Optional[str] = None) -> Dict[str, Any]:
    """
    Detects Punycode ('xn--') and Unicode homograph/confusable representations
    where non-ASCII characters visually mimic ASCII brand names.

    Prompt Requirement:
    "The domain contains a Unicode/punycode representation
    that may visually resemble another domain."
    """
    if not hostname:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or url.split("/")[0].split(":")[0]

    hostname = (hostname or "").strip().lower()
    has_punycode = "xn--" in hostname
    has_non_ascii = any(ord(c) > 127 for c in hostname)

    unicode_domain = hostname
    ascii_resemblance = None
    is_homograph = False
    homoglyphs_detected = []

    # If domain has punycode 'xn--', decode it to its Unicode representation
    if has_punycode:
        try:
            unicode_domain = hostname.encode("ascii").decode("idna")
        except Exception:
            unicode_domain = hostname

    # Scan for confusable homoglyphs in the Unicode domain
    resembled_chars = []
    for ch in unicode_domain:
        if ch in HOMOGLYPH_MAP:
            resembled_chars.append(HOMOGLYPH_MAP[ch])
            homoglyphs_detected.append(f"'{ch}' (mimics '{HOMOGLYPH_MAP[ch]}')")
            is_homograph = True
        else:
            resembled_chars.append(ch)

    if is_homograph or has_punycode:
        ascii_resemblance = "".join(resembled_chars)
        if ascii_resemblance == unicode_domain and not has_punycode:
            is_homograph = False
            ascii_resemblance = None

    detected = has_punycode or has_non_ascii or is_homograph

    warning = None
    if detected:
        # Exact prompt specification:
        warning = (
            "The domain contains a Unicode/punycode representation "
            "that may visually resemble another domain."
        )

    return {
        "detected": detected,
        "technique": "unicode_punycode",
        "has_punycode": has_punycode,
        "has_non_ascii": has_non_ascii,
        "is_homograph": is_homograph,
        "punycode_domain": hostname if has_punycode else None,
        "unicode_domain": unicode_domain,
        "visually_resembles": ascii_resemblance,
        "homoglyphs_detected": homoglyphs_detected,
        "warning": warning,
        "reasons": [
            f"Unicode/punycode homograph representation: '{unicode_domain}'"
            + (f" visually resembles '{ascii_resemblance}'." if ascii_resemblance else ".")
        ] if detected else []
    }


def check_url_encoding(url: str) -> Dict[str, Any]:
    r"""
    Detects evasive URL encoding techniques:
    - Double URL encoding (e.g. %252e, %252f, %2540)
    - Encoded hostnames (percent-encoding inside host authority)
    - Encoded directory traversal (%2e%2e%2f, %2e%2e/)
    - Encoded control characters / delimiters (%40 for @, %5c for \)
    - Over-encoded ASCII text in paths and queries
    """
    if not url:
        return {"detected": False, "technique": "url_encoding"}

    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""

    # 1. Double percent-encoding (%25 followed by two hex digits)
    double_encoded_matches = re.findall(r"%25([0-9a-fA-F]{2})", url)
    has_double_encoding = len(double_encoded_matches) > 0

    # 2. Percent-encoding in the hostname itself (e.g. %67%6f%6f%67%6c%65)
    host_has_percent = "%" in host

    # 3. Encoded traversal or delimiters
    has_encoded_traversal = bool(re.search(r"(?:%2e|\.){2}(?:%2f|%5c|/|\\)", url, re.IGNORECASE))
    has_encoded_at = "%40" in url.lower()
    has_encoded_slash = "%2f" in url.lower() or "%5c" in url.lower()

    # 4. Excessive percent encoding (> 3 distinct encoded octets)
    all_percent_octets = re.findall(r"%[0-9a-fA-F]{2}", url)
    excessive_encoding = len(all_percent_octets) >= 4

    detected = (
        has_double_encoding
        or host_has_percent
        or has_encoded_traversal
        or has_encoded_at
        or excessive_encoding
    )

    reasons = []
    if has_double_encoding:
        reasons.append("Double URL percent-encoding detected (%25xx), a signature filter-evasion technique.")
    if host_has_percent:
        reasons.append(f"Host authority contains percent-encoded bytes ('{host}'), disguising true destination.")
    if has_encoded_traversal:
        reasons.append("Path traversal evasion detected (%2e%2e%2f / directory traversal).")
    if has_encoded_at:
        reasons.append("Encoded '@' symbol (%40) detected, disguising embedded user authentication spoofing.")
    elif excessive_encoding:
        reasons.append(f"Excessive percent-encoding ({len(all_percent_octets)} encoded octets) concealing URL components.")

    decoded_url = urllib.parse.unquote(url)
    if has_double_encoding:
        decoded_url = urllib.parse.unquote(decoded_url)

    warning = None
    if detected:
        warning = "The URL utilizes evasive percent-encoding to conceal destination paths or bypass filters."

    return {
        "detected": detected,
        "technique": "url_encoding",
        "has_double_encoding": has_double_encoding,
        "host_has_percent": host_has_percent,
        "has_encoded_traversal": has_encoded_traversal,
        "has_encoded_at": has_encoded_at,
        "has_encoded_slash": has_encoded_slash,
        "excessive_encoding": excessive_encoding,
        "encoded_octets_count": len(all_percent_octets),
        "decoded_url": decoded_url if detected else None,
        "warning": warning,
        "reasons": reasons
    }


def check_hex_alternative_ip(url: str, hostname: Optional[str] = None) -> Dict[str, Any]:
    """
    Detects obfuscated IP address representations that evade standard string filters:
    - Hexadecimal notation: 0x7f.0x0.0x0.0x1, 0x7f000001
    - DWORD / Decimal integer notation: http://2130706433 (127.0.0.1)
    - Octal notation: 0177.0.0.01
    - Mixed base notation: 0x7f.1
    """
    if not hostname:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or url.split("/")[0].split(":")[0]

    host = (hostname or "").strip().lower()
    if not host:
        return {"detected": False, "technique": "hex_alternative_ip"}

    is_hex_ip = False
    is_dword_ip = False
    is_octal_ip = False
    canonical_ip = None

    # 1. Check Hex IP: e.g. 0x7f000001 or 0x7f.0x0.0x0.0x1 or 0x7f.0.0.1
    if host.startswith("0x") or ".0x" in host:
        try:
            parts = host.split(".")
            if len(parts) == 1 and host.startswith("0x"):
                # Single 32-bit hex integer
                val = int(host, 16)
                if 0 <= val <= 4294967295:
                    canonical_ip = str(ipaddress.IPv4Address(val))
                    is_hex_ip = True
            elif len(parts) == 4:
                # Dotted hex
                octets = [int(p, 16) if p.startswith("0x") else int(p) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    canonical_ip = ".".join(str(o) for o in octets)
                    is_hex_ip = True
        except Exception:
            pass

    # 2. Check DWORD / Pure integer IP: e.g. 2130706433 or 3232235521
    if not is_hex_ip and host.isdigit():
        try:
            val = int(host)
            if 0 <= val <= 4294967295:
                canonical_ip = str(ipaddress.IPv4Address(val))
                is_dword_ip = True
        except Exception:
            pass

    # 3. Check Octal IP: e.g. 0177.0.0.01 (octets with leading zeros)
    if not is_hex_ip and not is_dword_ip and "." in host:
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            has_leading_zero = any(len(p) > 1 and p.startswith("0") for p in parts)
            if has_leading_zero:
                try:
                    octets = [int(p, 8) if (len(p) > 1 and p.startswith("0")) else int(p) for p in parts]
                    if all(0 <= o <= 255 for o in octets):
                        canonical_ip = ".".join(str(o) for o in octets)
                        is_octal_ip = True
                except Exception:
                    pass

    detected = is_hex_ip or is_dword_ip or is_octal_ip

    reasons = []
    warning = None
    if detected:
        subtype = "Hexadecimal" if is_hex_ip else ("DWORD (Integer)" if is_dword_ip else "Octal")
        warning = f"The URL uses an alternative {subtype} IP representation ({host} -> {canonical_ip}) to evade domain filters."
        reasons.append(f"Obfuscated {subtype} IP address notation: '{host}' resolves to canonical '{canonical_ip}'.")

    return {
        "detected": detected,
        "technique": "hex_alternative_ip",
        "is_hex_ip": is_hex_ip,
        "is_dword_ip": is_dword_ip,
        "is_octal_ip": is_octal_ip,
        "original_host": host,
        "canonical_ip": canonical_ip,
        "warning": warning,
        "reasons": reasons
    }


def check_nested_urls(url: str) -> Dict[str, Any]:
    """
    Detects nested URLs embedded inside query parameters or path segments.
    Used for open-redirect abuse, credential token forwarding, and gateway disguise.
    e.g. https://login.company.com.tracker.com/r?dest=https://phishing.xyz/login
    """
    if not url:
        return {"detected": False, "technique": "nested_urls"}

    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    outer_host = (parsed.hostname or "").lower()

    nested_urls = []
    cross_domain_nested = []

    # 1. Inspect Query Parameters
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for k, v_list in query_params.items():
        k_clean = k.lower()
        for v in v_list:
            # Check unquoted and raw values
            v_unquoted = urllib.parse.unquote(v).strip()
            if v_unquoted.lower().startswith(("http://", "https://", "ftp://")):
                nested_urls.append(v_unquoted)
                inner_parsed = urllib.parse.urlparse(v_unquoted)
                inner_host = (inner_parsed.hostname or "").lower()
                if inner_host and inner_host != outer_host:
                    cross_domain_nested.append({
                        "param": k,
                        "nested_url": v_unquoted,
                        "inner_host": inner_host,
                        "outer_host": outer_host
                    })
            # Also check if value looks like a naked domain (e.g. dest=evil-phish.com/login)
            elif k_clean in NESTED_URL_PARAM_KEYS and "." in v_unquoted and not " " in v_unquoted and "/" in v_unquoted:
                candidate = f"https://{v_unquoted}"
                inner_parsed = urllib.parse.urlparse(candidate)
                inner_host = (inner_parsed.hostname or "").lower()
                if inner_host and inner_host != outer_host and not inner_host.endswith(outer_host):
                    nested_urls.append(candidate)
                    cross_domain_nested.append({
                        "param": k,
                        "nested_url": candidate,
                        "inner_host": inner_host,
                        "outer_host": outer_host
                    })

    # 2. Inspect Path Segments for embedded full URLs
    path_unquoted = urllib.parse.unquote(parsed.path)
    url_matches_in_path = re.findall(r"(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?", path_unquoted)
    for m in url_matches_in_path:
        full_m = m if m.startswith("http") else f"https://{m}"
        if full_m not in nested_urls:
            nested_urls.append(full_m)
            inner_parsed = urllib.parse.urlparse(full_m)
            inner_host = (inner_parsed.hostname or "").lower()
            if inner_host and inner_host != outer_host:
                cross_domain_nested.append({
                    "param": "path_segment",
                    "nested_url": full_m,
                    "inner_host": inner_host,
                    "outer_host": outer_host
                })

    detected = len(nested_urls) > 0
    is_cross_domain = len(cross_domain_nested) > 0

    reasons = []
    warning = None
    if detected:
        primary_nested = nested_urls[0]
        if is_cross_domain:
            target_host = cross_domain_nested[0]["inner_host"]
            warning = f"The URL conceals an external destination ('{target_host}') inside parameters (open redirect / nested URL obfuscation)."
            reasons.append(f"Nested URL obfuscation: Parameter forwards traffic to external host '{target_host}'.")
        else:
            warning = "The URL embeds an internal sub-destination within its parameter payload."
            reasons.append(f"Embedded nested URL detected in parameters: {primary_nested[:80]}")

    return {
        "detected": detected,
        "technique": "nested_urls",
        "has_nested_url": detected,
        "is_cross_domain": is_cross_domain,
        "nested_urls": nested_urls,
        "primary_nested_url": nested_urls[0] if nested_urls else None,
        "cross_domain_details": cross_domain_nested,
        "warning": warning,
        "reasons": reasons
    }


def trace_redirect_chain(url: str, max_hops: int = 5) -> Dict[str, Any]:
    """
    Safely traces redirect hops without downloading untrusted bodies or executing scripts.
    Identifies multiple redirects (redirect chaining / bounce evasion) when hop count >= 2.
    """
    if not url or not isinstance(url, str):
        return {"detected": False, "hop_count": 0, "chain": []}

    clean_url = url.strip()
    cache_key = clean_url.lower()
    now_ts = time.time()

    if cache_key in _REDIRECT_CHAIN_CACHE:
        cached_ts, cached_data = _REDIRECT_CHAIN_CACHE[cache_key]
        if now_ts - cached_ts < CACHE_TTL:
            return cached_data

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 QRQuishingInspector/2.0"
    }

    chain = [clean_url]
    current_url = clean_url
    hop_count = 0

    try:
        with httpx.Client(timeout=2.0, follow_redirects=False, verify=False) as client:
            while hop_count < max_hops:
                try:
                    resp = client.head(current_url, headers=headers)
                    if resp.status_code == 405:
                        with client.stream("GET", current_url, headers=headers) as stream_resp:
                            status_code = stream_resp.status_code
                            location = stream_resp.headers.get("Location")
                    else:
                        status_code = resp.status_code
                        location = resp.headers.get("Location")
                except Exception:
                    break

                if status_code in (301, 302, 303, 307, 308) and location:
                    hop_count += 1
                    # Resolve relative redirect targets
                    next_url = urllib.parse.urljoin(current_url, location)
                    if next_url in chain:
                        # Redirect loop detected
                        chain.append(f"{next_url} (Loop)")
                        break
                    chain.append(next_url)
                    current_url = next_url
                else:
                    break
    except Exception as e:
        logger.debug(f"Redirect chain trace error for {clean_url}: {e}")

    has_multiple_redirects = hop_count >= 2
    detected = has_multiple_redirects

    reasons = []
    warning = None
    if has_multiple_redirects:
        warning = f"Multiple redirects detected ({hop_count} hops). Bouncing traffic through intermediary domains to evade scanning."
        reasons.append(f"Multiple redirects detected ({hop_count} hops): {' -> '.join(chain[:4])}")

    result = {
        "detected": detected,
        "technique": "multiple_redirects",
        "has_multiple_redirects": has_multiple_redirects,
        "hop_count": hop_count,
        "chain": chain,
        "final_destination": chain[-1] if len(chain) > 1 else None,
        "warning": warning,
        "reasons": reasons
    }

    _REDIRECT_CHAIN_CACHE[cache_key] = (now_ts, result)
    return result


def detect_obfuscation(url: str, check_redirects: bool = True) -> Dict[str, Any]:
    """
    Consolidated Anti-Obfuscation Detection Engine.
    Executes all 5 detection modules and returns a structured analysis object.
    """
    if not url:
        return {
            "is_obfuscated": False,
            "detected_techniques": [],
            "techniques_count": 0,
            "warning_title": "No Obfuscation Detected",
            "warning_message": "Destination does not exhibit evasive obfuscation techniques.",
            "penalty": 0,
            "reasons": [],
            "punycode_info": None,
            "encoding_info": None,
            "ip_obfuscation_info": None,
            "nested_url_info": None,
            "redirect_chain_info": None
        }

    # Run individual detectors
    punycode_res = check_unicode_punycode(url)
    encoding_res = check_url_encoding(url)
    ip_res = check_hex_alternative_ip(url)
    nested_res = check_nested_urls(url)
    redirect_res = trace_redirect_chain(url) if check_redirects else {
        "detected": False, "technique": "multiple_redirects", "hop_count": 0, "chain": [url]
    }

    detected_techniques = []
    penalty = 0
    all_reasons = []
    primary_warning_msg = None

    # 1. Unicode / Punycode (Highest priority for warning format match)
    if punycode_res["detected"]:
        detected_techniques.append("unicode_punycode")
        penalty += 45
        all_reasons.extend(punycode_res["reasons"])
        # Exact prompt specification:
        primary_warning_msg = (
            "The domain contains a Unicode/punycode representation "
            "that may visually resemble another domain."
        )

    # 2. Hex / Alternative IP
    if ip_res["detected"]:
        detected_techniques.append("hex_alternative_ip")
        penalty += 40
        all_reasons.extend(ip_res["reasons"])
        if not primary_warning_msg:
            primary_warning_msg = ip_res["warning"]

    # 3. URL Encoding
    if encoding_res["detected"]:
        detected_techniques.append("url_encoding")
        penalty += 30
        all_reasons.extend(encoding_res["reasons"])
        if not primary_warning_msg:
            primary_warning_msg = encoding_res["warning"]

    # 4. Nested URLs
    if nested_res["detected"]:
        detected_techniques.append("nested_urls")
        penalty += 35
        all_reasons.extend(nested_res["reasons"])
        if not primary_warning_msg:
            primary_warning_msg = nested_res["warning"]

    # 5. Multiple Redirects
    if redirect_res["detected"]:
        detected_techniques.append("multiple_redirects")
        penalty += 25
        all_reasons.extend(redirect_res["reasons"])
        if not primary_warning_msg:
            primary_warning_msg = redirect_res["warning"]

    is_obfuscated = len(detected_techniques) > 0
    warning_title = "⚠ POSSIBLE URL OBFUSCATION" if is_obfuscated else "No Obfuscation Detected"
    warning_message = primary_warning_msg or "Destination does not exhibit evasive obfuscation techniques."

    return {
        "is_obfuscated": is_obfuscated,
        "detected_techniques": detected_techniques,
        "techniques_count": len(detected_techniques),
        "warning_title": warning_title,
        "warning_message": warning_message,
        "penalty": min(penalty, 60),
        "reasons": all_reasons,
        "punycode_info": punycode_res if punycode_res["detected"] else None,
        "encoding_info": encoding_res if encoding_res["detected"] else None,
        "ip_obfuscation_info": ip_res if ip_res["detected"] else None,
        "nested_url_info": nested_res if nested_res["detected"] else None,
        "redirect_chain_info": redirect_res if redirect_res["detected"] else None
    }
