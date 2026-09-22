r"""
Brand Impersonation Detection Engine for QR-Quishing-Inspector.

Detects unauthorized brand impersonation, typosquatting, character substitutions (leetspeak),
misleading subdomains, and deceptive compound domain names targeting high-value organizations.

Produces exact security alerts:
    ⚠ POSSIBLE BRAND IMPERSONATION
    Detected brand-like term: Google
    Actual domain: google-security-example.com
    The domain is not an official Google domain.

Includes strict false-positive suppression for official brand domains and benign dictionary words.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set

# Comprehensive brand profiles with official registered domains and canonical identifiers
BRAND_PROFILES: Dict[str, Dict[str, Any]] = {
    "Google": {
        "canonical": "google",
        "tokens": ["google"],
        "official_domains": {
            "google.com", "google.co.uk", "google.ca", "google.de", "google.fr",
            "google.co.in", "google.com.br", "google.com.au", "google.co.jp",
            "google.org", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "youtube.com", "gmail.com", "android.com", "googlevideo.com",
            "waze.com", "chromium.org", "googlemail.com", "withgoogle.com",
            "googleblog.com", "thinkwithgoogle.com"
        },
        "target_keywords": {
            "login", "signin", "security", "verification", "verify", "account",
            "recovery", "drive", "docs", "workspace", "auth", "portal", "support"
        }
    },
    "Microsoft": {
        "canonical": "microsoft",
        "tokens": ["microsoft", "msft", "office365"],
        "official_domains": {
            "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com",
            "windows.com", "microsoftonline.com", "azure.com", "msn.com", "bing.com",
            "skype.com", "sharepoint.com", "onedrive.com", "visualstudio.com",
            "xbox.com", "microsoft365.com", "msftconnecttest.com", "azurewebsites.net"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "account", "support",
            "portal", "auth", "admin", "tenant", "365", "recovery", "password"
        }
    },
    "PayPal": {
        "canonical": "paypal",
        "tokens": ["paypal"],
        "official_domains": {
            "paypal.com", "paypal.me", "paypal-community.com", "paypalobjects.com",
            "venmo.com", "paypal-communication.com", "braintreepayments.com"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "verification", "account",
            "resolution", "billing", "invoice", "wallet", "dispute", "update", "confirm"
        }
    },
    "Apple": {
        "canonical": "apple",
        "tokens": ["apple", "icloud"],
        "official_domains": {
            "apple.com", "icloud.com", "apple-dns.net", "aaplimg.com",
            "mzstatic.com", "appleid.apple.com", "itunes.com", "me.com"
        },
        "target_keywords": {
            "id", "login", "signin", "verify", "verification", "support",
            "account", "device", "findmy", "security", "billing", "unlock"
        }
    },
    "Amazon": {
        "canonical": "amazon",
        "tokens": ["amazon"],
        "official_domains": {
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp",
            "amazon.fr", "amazon.es", "amazon.it", "amazon.in", "amazon.com.au",
            "aws.amazon.com", "media-amazon.com", "primevideo.com", "amazontrust.com",
            "amazonwebservices.com", "a2z.com"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "order", "delivery",
            "account", "billing", "prime", "support", "package", "refund"
        }
    },
    "Netflix": {
        "canonical": "netflix",
        "tokens": ["netflix"],
        "official_domains": {
            "netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net", "nflxso.net"
        },
        "target_keywords": {
            "login", "signin", "billing", "account", "payment", "membership",
            "verify", "update", "reactivate"
        }
    },
    "Chase": {
        "canonical": "chase",
        "tokens": ["chase"],
        "official_domains": {
            "chase.com", "jpmorganchase.com", "jpmorgan.com"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "online", "banking",
            "account", "card", "alert", "fraud", "auth"
        }
    },
    "Bank of America": {
        "canonical": "bankofamerica",
        "tokens": ["bankofamerica", "bofa"],
        "official_domains": {
            "bankofamerica.com", "bofa.com", "merrilledge.com", "merrill.com"
        },
        "target_keywords": {
            "login", "signin", "online", "banking", "verify", "account",
            "security", "auth", "card", "alert"
        }
    },
    "Wells Fargo": {
        "canonical": "wellsfargo",
        "tokens": ["wellsfargo"],
        "official_domains": {
            "wellsfargo.com", "wf.com"
        },
        "target_keywords": {
            "login", "signin", "online", "banking", "verify", "account",
            "security", "auth", "card", "alert"
        }
    },
    "Meta": {
        "canonical": "meta",
        "tokens": ["facebook", "instagram", "whatsapp", "meta"],
        "official_domains": {
            "facebook.com", "meta.com", "instagram.com", "whatsapp.com",
            "fb.com", "messenger.com", "oculus.com", "whatsapp.net",
            "fbsbx.com", "cdninstagram.com"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "checkpoint", "appeal",
            "copyright", "account", "recover", "badge", "business"
        }
    },
    "DHL": {
        "canonical": "dhl",
        "tokens": ["dhl"],
        "official_domains": {
            "dhl.com", "dhl-usa.com", "dhl.de", "dhl.co.uk", "dhl-express.com"
        },
        "target_keywords": {
            "track", "tracking", "delivery", "parcel", "package", "fee",
            "customs", "shipping", "redelivery", "address"
        }
    },
    "FedEx": {
        "canonical": "fedex",
        "tokens": ["fedex"],
        "official_domains": {
            "fedex.com"
        },
        "target_keywords": {
            "track", "tracking", "delivery", "parcel", "package", "fee",
            "shipping", "redelivery", "notification"
        }
    },
    "USPS": {
        "canonical": "usps",
        "tokens": ["usps"],
        "official_domains": {
            "usps.com", "usps.gov"
        },
        "target_keywords": {
            "track", "tracking", "delivery", "parcel", "package", "redelivery",
            "fee", "address", "notification"
        }
    },
    "Binance": {
        "canonical": "binance",
        "tokens": ["binance"],
        "official_domains": {
            "binance.com", "binance.us", "binance.org"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "wallet", "crypto",
            "withdraw", "auth", "2fa"
        }
    },
    "Coinbase": {
        "canonical": "coinbase",
        "tokens": ["coinbase"],
        "official_domains": {
            "coinbase.com", "coinbase.pro"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "wallet", "crypto",
            "auth", "recovery"
        }
    },
    "Adobe": {
        "canonical": "adobe",
        "tokens": ["adobe"],
        "official_domains": {
            "adobe.com", "adobe.io", "acrobat.com"
        },
        "target_keywords": {
            "login", "signin", "document", "sign", "pdf", "verify", "account"
        }
    },
    "Spotify": {
        "canonical": "spotify",
        "tokens": ["spotify"],
        "official_domains": {
            "spotify.com", "scdn.co", "spotifycdn.com"
        },
        "target_keywords": {
            "login", "billing", "premium", "account", "update", "verify"
        }
    },
    "Dropbox": {
        "canonical": "dropbox",
        "tokens": ["dropbox"],
        "official_domains": {
            "dropbox.com", "dropboxstatic.com"
        },
        "target_keywords": {
            "login", "signin", "share", "file", "document", "verify"
        }
    },
    "LinkedIn": {
        "canonical": "linkedin",
        "tokens": ["linkedin"],
        "official_domains": {
            "linkedin.com", "licdn.com"
        },
        "target_keywords": {
            "login", "signin", "security", "verify", "message", "invitation", "account"
        }
    }
}

# General deceptive/phishing keywords frequently paired with brand terms
GENERAL_DECEPTIVE_KEYWORDS: Set[str] = {
    "security", "login", "signin", "verify", "verification", "account", "support",
    "auth", "authentication", "portal", "update", "banking", "service", "billing",
    "recover", "recovery", "help", "secure", "confirm", "confirmation", "alert",
    "customer", "online", "passcode", "wallet", "protection", "validate",
    "validation", "session", "checkpoint", "notice", "center", "desk", "manage"
}

# Common benign dictionary words that happen to contain brand substrings
BENIGN_DICTIONARY_WORDS: Set[str] = {
    "pineapple", "pineapples", "grapple", "applecider", "applesauce",
    "metadata", "metaphor", "metabolism", "metallurgy",
    "amazonas", "amazonian",
    "toggle", "goggle", "goggles", "boggle", "boogle",
    "apply", "applicant", "application",
    "chased", "chasing", "chaser",
    "officer", "officers", "offices", "example", "examples"
}

# Leetspeak substitution mappings
LEET_CHAR_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
}

LEET_MULTI_MAP: List[Tuple[str, str, str]] = [
    ("00", "oo", "'00' substituted for 'oo'"),
    ("vv", "w", "'vv' substituted for 'w'"),
    ("rn", "m", "'rn' substituted for 'm'"),
    ("cl", "d", "'cl' substituted for 'd'"),
]


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes classic Damerau-Levenshtein distance between two strings,
    supporting insertions, deletions, substitutions, and adjacent transpositions.
    """
    len1, len2 = len(s1), len(s2)
    if s1 == s2:
        return 0
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    d: Dict[Tuple[int, int], int] = {}
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


def calculate_similarity(s1: str, s2: str) -> float:
    """Calculates normalized similarity ratio [0.0 - 1.0]."""
    if not s1 or not s2:
        return 0.0
    dist = damerau_levenshtein_distance(s1.lower(), s2.lower())
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return max(0.0, 1.0 - (dist / max_len))


def normalize_leetspeak(token: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    De-obfuscates leetspeak characters in a token and records substitutions.
    e.g. 'paypa1' -> ('paypal', [{'char': '1', 'replaced': 'l', ...}])
         'micr0soft' -> ('microsoft', [{'char': '0', 'replaced': 'o', ...}])
         'g00gle' -> ('google', [{'char': '00', 'replaced': 'oo', ...}])
    """
    normalized = token.lower()
    substitutions: List[Dict[str, str]] = []

    # First handle multi-character patterns (e.g. '00' -> 'oo', 'rn' -> 'm')
    for pattern, replacement, desc in LEET_MULTI_MAP:
        if pattern in normalized:
            count = normalized.count(pattern)
            normalized = normalized.replace(pattern, replacement)
            substitutions.append({
                "original": pattern,
                "normalized": replacement,
                "description": desc,
                "count": count
            })

    # Then handle single characters
    chars = list(normalized)
    for idx, ch in enumerate(chars):
        if ch in LEET_CHAR_MAP:
            rep = LEET_CHAR_MAP[ch]
            substitutions.append({
                "original": ch,
                "normalized": rep,
                "description": f"'{ch}' substituted for '{rep}'",
                "position": idx
            })
            chars[idx] = rep

    return "".join(chars), substitutions


def is_official_brand_domain(hostname: str, brand_name: str) -> bool:
    """
    Checks if a hostname is an authoritative official domain of the brand.
    Strictly prevents false positives for legitimate corporate domains and subdomains.
    """
    if not hostname or brand_name not in BRAND_PROFILES:
        return False

    clean_host = hostname.lower().strip()
    official_domains = BRAND_PROFILES[brand_name]["official_domains"]

    for official in official_domains:
        if clean_host == official or clean_host.endswith("." + official):
            return True

    return False


def extract_host_and_domain(url_or_domain: str) -> Tuple[str, str, List[str]]:
    """
    Extracts canonical hostname, registered domain, and subdomains list.
    """
    target = url_or_domain.strip()
    if "://" not in target:
        target = f"https://{target}"

    try:
        parsed = urllib.parse.urlparse(target)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        hostname = target.split("/")[0].lower()

    if not hostname:
        return "", "", []

    # Strip port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    parts = hostname.split(".")
    if len(parts) <= 1:
        return hostname, hostname, []

    # Handle common two-part TLDs (e.g. co.uk, com.au, com.br, co.jp)
    two_part_tlds = {"co.uk", "com.au", "com.br", "co.jp", "co.in", "org.uk", "gov.uk", "us.gov"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        registered_domain = ".".join(parts[-3:])
        subdomains = parts[:-3]
    else:
        registered_domain = ".".join(parts[-2:])
        subdomains = parts[:-2]

    return hostname, registered_domain, subdomains


def detect_brand_impersonation(url_or_domain: str) -> Dict[str, Any]:
    """
    Analyzes a URL or domain for unauthorized brand impersonation across:
    1. Brand-like names in domains (exact/compound keywords)
    2. Character substitutions / Leetspeak (0->o, 1->l, 00->oo)
    3. Suspicious typosquatting similarity (Levenshtein/Damerau-Levenshtein)
    4. Misleading subdomains (e.g. google.com.phishing-site.xyz)

    Produces exact prompt results:
        ⚠ POSSIBLE BRAND IMPERSONATION
        Detected brand-like term: {Brand}
        Actual domain: {domain}
        The domain is not an official {Brand} domain.

    Returns dict conforming to BrandImpersonationDetail schema.
    """
    hostname, registered_domain, subdomains = extract_host_and_domain(url_or_domain)

    default_result: Dict[str, Any] = {
        "is_impersonation": False,
        "warning_title": "No Brand Impersonation Detected",
        "detected_brand": None,
        "actual_domain": registered_domain or hostname or url_or_domain,
        "warning_message": "Domain does not exhibit brand impersonation characteristics.",
        "impersonation_types": [],
        "substitutions": [],
        "similarity_score": None,
        "matched_token": None,
        "is_official_domain": False,
        "official_domains_sample": [],
        "penalty": 0,
        "reasons": []
    }

    if not hostname or not registered_domain:
        return default_result

    # 1. False Positive Pre-Check: If registered domain or hostname is an official domain of ANY brand, exit safely!
    for b_name, b_data in BRAND_PROFILES.items():
        if is_official_brand_domain(hostname, b_name):
            default_result["is_official_domain"] = True
            default_result["official_domains_sample"] = sorted(list(b_data["official_domains"]))[:5]
            return default_result

    # Extract base domain name without TLD (e.g. 'paypa1-login' from 'paypa1-login.com')
    reg_parts = registered_domain.split(".")
    base_domain_name = reg_parts[0] if len(reg_parts) > 1 else registered_domain

    # Tokenize the base domain by hyphens, underscores, and dots
    tokens = [t for t in re.split(r"[-_.]", base_domain_name) if t]

    # Full subdomain string
    subdomain_str = ".".join(subdomains).lower()

    # -------------------------------------------------------------
    # Pillar A: Misleading Subdomain Detection
    # (e.g. 'google.com.phishing-site.xyz' or 'paypal.com.verify.net')
    # -------------------------------------------------------------
    if subdomains:
        for b_name, b_data in BRAND_PROFILES.items():
            # Check if any official domain of the brand appears in subdomains
            for off_d in b_data["official_domains"]:
                if off_d in subdomain_str or subdomain_str.endswith(off_d):
                    msg = f"The domain is not an official {b_name} domain."
                    return {
                        "is_impersonation": True,
                        "warning_title": "⚠ POSSIBLE BRAND IMPERSONATION",
                        "detected_brand": b_name,
                        "actual_domain": registered_domain,
                        "warning_message": msg,
                        "impersonation_types": ["misleading_subdomain"],
                        "substitutions": [],
                        "similarity_score": 1.0,
                        "matched_token": off_d,
                        "is_official_domain": False,
                        "official_domains_sample": sorted(list(b_data["official_domains"]))[:5],
                        "penalty": 45,
                        "reasons": [
                            f"Misleading subdomain: '{off_d}' is embedded in subdomain '{subdomain_str}', but registered domain is '{registered_domain}'.",
                            msg
                        ]
                    }

            # Check if brand canonical token appears as an exact subdomain label
            for tok in b_data["tokens"]:
                if tok in subdomains and not is_official_brand_domain(hostname, b_name):
                    msg = f"The domain is not an official {b_name} domain."
                    return {
                        "is_impersonation": True,
                        "warning_title": "⚠ POSSIBLE BRAND IMPERSONATION",
                        "detected_brand": b_name,
                        "actual_domain": registered_domain,
                        "warning_message": msg,
                        "impersonation_types": ["misleading_subdomain"],
                        "substitutions": [],
                        "similarity_score": 1.0,
                        "matched_token": tok,
                        "is_official_domain": False,
                        "official_domains_sample": sorted(list(b_data["official_domains"]))[:5],
                        "penalty": 40,
                        "reasons": [
                            f"Misleading subdomain label: '{tok}' appears as subdomain on unauthorized domain '{registered_domain}'.",
                            msg
                        ]
                    }

    # -------------------------------------------------------------
    # Pillar B: Brand Impersonation Candidates Collection
    # Evaluate across all brands and select the most confident match:
    # Priority:
    # 1. Exact brand token in unauthorized domain (score = 100)
    # 2. Leetspeak / Character Substitution match (score = 90)
    # 3. Concatenation with deceptive keyword (score = 80)
    # 4. Typosquatting / Similarity (score = 70 * similarity)
    # -------------------------------------------------------------
    candidates: List[Dict[str, Any]] = []

    for b_name, b_data in BRAND_PROFILES.items():
        brand_tokens = b_data["tokens"]
        brand_keywords = b_data.get("target_keywords", set()).union(GENERAL_DECEPTIVE_KEYWORDS)

        # Check each token in base domain name
        for raw_token in tokens:
            clean_token = raw_token.lower()

            # Guard against benign dictionary words
            if clean_token in BENIGN_DICTIONARY_WORDS:
                continue

            # B.1: Exact Brand Token in Compound Domain
            # e.g. 'google-security-example.com', 'paypal-login.com'
            for target_b_token in brand_tokens:
                if clean_token == target_b_token:
                    msg = f"The domain is not an official {b_name} domain."
                    has_deceptive_kw = any(t in brand_keywords for t in tokens if t != clean_token)
                    kw_note = " combined with security/account keywords" if has_deceptive_kw else ""
                    imp_types = ["compound_keyword"] if has_deceptive_kw else ["brand_name_in_domain"]

                    candidates.append({
                        "priority": 100,
                        "is_impersonation": True,
                        "warning_title": "⚠ POSSIBLE BRAND IMPERSONATION",
                        "detected_brand": b_name,
                        "actual_domain": registered_domain,
                        "warning_message": msg,
                        "impersonation_types": imp_types,
                        "substitutions": [],
                        "similarity_score": 1.0,
                        "matched_token": clean_token,
                        "is_official_domain": False,
                        "official_domains_sample": sorted(list(b_data["official_domains"]))[:5],
                        "penalty": 40 if has_deceptive_kw else 35,
                        "reasons": [
                            f"Detected brand-like term '{b_name}' in domain token '{clean_token}'{kw_note}.",
                            msg
                        ]
                    })

            # B.2: Leetspeak / Character Substitution Check
            # e.g. 'paypa1' -> 'paypal', 'micr0soft' -> 'microsoft', 'g00gle' -> 'google'
            norm_token, substitutions = normalize_leetspeak(clean_token)
            if substitutions:
                for target_b_token in brand_tokens:
                    if norm_token == target_b_token and clean_token != target_b_token:
                        msg = f"The domain is not an official {b_name} domain."
                        sub_desc = ", ".join([s["description"] for s in substitutions])
                        has_deceptive_kw = any(t in brand_keywords for t in tokens if t != clean_token)
                        imp_types = ["character_substitution"]
                        if has_deceptive_kw:
                            imp_types.append("compound_keyword")

                        candidates.append({
                            "priority": 90,
                            "is_impersonation": True,
                            "warning_title": "⚠ POSSIBLE BRAND IMPERSONATION",
                            "detected_brand": b_name,
                            "actual_domain": registered_domain,
                            "warning_message": msg,
                            "impersonation_types": imp_types,
                            "substitutions": substitutions,
                            "similarity_score": calculate_similarity(clean_token, target_b_token),
                            "matched_token": clean_token,
                            "is_official_domain": False,
                            "official_domains_sample": sorted(list(b_data["official_domains"]))[:5],
                            "penalty": 45,
                            "reasons": [
                                f"Character substitution detected in domain token '{clean_token}' ({sub_desc}) mimicking '{b_name}'.",
                                msg
                            ]
                        })

            # B.3: Typosquatting / Suspicious Similarity Check
            # Skip if token is a standard deceptive keyword (e.g. 'login', 'security') to avoid false positives
            if clean_token not in GENERAL_DECEPTIVE_KEYWORDS and clean_token not in brand_keywords:
                for target_b_token in brand_tokens:
                    if len(clean_token) >= 4 and abs(len(clean_token) - len(target_b_token)) <= 2:
                        dist = damerau_levenshtein_distance(clean_token, target_b_token)
                        sim = calculate_similarity(clean_token, target_b_token)
                        max_allowed_dist = 2 if len(target_b_token) >= 7 else 1

                        if 1 <= dist <= max_allowed_dist and sim >= 0.80:
                            msg = f"The domain is not an official {b_name} domain."
                            candidates.append({
                                "priority": int(70 * sim),
                                "is_impersonation": True,
                                "warning_title": "⚠ POSSIBLE BRAND IMPERSONATION",
                                "detected_brand": b_name,
                                "actual_domain": registered_domain,
                                "warning_message": msg,
                                "impersonation_types": ["typosquatting"],
                                "substitutions": [],
                                "similarity_score": round(sim, 3),
                                "matched_token": clean_token,
                                "is_official_domain": False,
                                "official_domains_sample": sorted(list(b_data["official_domains"]))[:5],
                                "penalty": 38,
                                "reasons": [
                                f"Typosquatting detected: token '{clean_token}' is suspiciously similar to '{b_name}' ({round(sim * 100, 1)}% similarity, edit distance {dist}).",
                                msg
                            ]
                        })

    # Concatenated Brand Names without Delimiters (e.g. 'googlelogin.xyz')
    for b_name, b_data in BRAND_PROFILES.items():
        for target_b_token in b_data["tokens"]:
            if len(target_b_token) >= 4:
                for kw in b_data.get("target_keywords", set()).union(GENERAL_DECEPTIVE_KEYWORDS):
                    if base_domain_name == f"{target_b_token}{kw}" or base_domain_name == f"{kw}{target_b_token}":
                        msg = f"The domain is not an official {b_name} domain."
                        candidates.append({
                            "priority": 85,
                            "is_impersonation": True,
                            "warning_title": "⚠ POSSIBLE BRAND IMPERSONATION",
                            "detected_brand": b_name,
                            "actual_domain": registered_domain,
                            "warning_message": msg,
                            "impersonation_types": ["compound_keyword"],
                            "substitutions": [],
                            "similarity_score": 1.0,
                            "matched_token": target_b_token,
                            "is_official_domain": False,
                            "official_domains_sample": sorted(list(b_data["official_domains"]))[:5],
                            "penalty": 40,
                            "reasons": [
                                f"Deceptive brand concatenation: '{base_domain_name}' combines brand '{b_name}' with keyword '{kw}'.",
                                msg
                            ]
                        })

    if candidates:
        # Sort candidates by priority descending, then similarity_score descending
        candidates.sort(key=lambda c: (c.get("priority", 0), c.get("similarity_score", 0)), reverse=True)
        winner = candidates[0]
        winner.pop("priority", None)
        return winner

    return default_result
