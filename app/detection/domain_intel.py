import time
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import httpx
import whois
import dns.resolver
import dns.exception

from app.detection.normalizer import normalize_url

logger = logging.getLogger("domain_intel")

# In-memory TTL cache for domain intelligence
# Cache format: {domain_key: (timestamp, data_dict)}
_DOMAIN_INTEL_CACHE: Dict[str, tuple[float, dict]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


def _normalize_datetime(val: Any) -> Optional[datetime]:
    """Convert variable date representations into timezone-aware UTC datetime."""
    if val is None:
        return None
    if isinstance(val, list):
        for item in val:
            parsed = _normalize_datetime(item)
            if parsed:
                return parsed
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, str):
        try:
            clean = val.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d"):
                try:
                    dt = datetime.strptime(val.strip(), fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except Exception:
                    continue
    return None


def _format_age(age_days: int) -> str:
    """Format integer days into human-friendly age string."""
    if age_days < 0:
        return "0 days"
    if age_days == 1:
        return "1 day"
    if age_days < 30:
        return f"{age_days} days"
    months = age_days // 30
    if months < 12:
        return f"{months} month{'s' if months != 1 else ''}"
    years = age_days // 365
    remaining_months = (age_days % 365) // 30
    if remaining_months > 0 and years < 3:
        return f"{years} year{'s' if years != 1 else ''}, {remaining_months} mo"
    return f"{years} year{'s' if years != 1 else ''}"


def _query_whois_socket(domain: str) -> Optional[dict]:
    """Query WHOIS using python-whois via socket port 43."""
    try:
        w = whois.whois(domain)
        creation = _normalize_datetime(w.creation_date)
        expiration = _normalize_datetime(w.expiration_date)

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        now = datetime.now(timezone.utc)
        age_days = None
        age_text = None
        is_recently_registered = False
        warning = None

        if creation:
            age_days = max(0, (now - creation).days)
            age_text = _format_age(age_days)
            if age_days <= 30:
                is_recently_registered = True
                warning = "⚠ Recently registered domain"

        return {
            "domain": domain,
            "creation_date": creation.strftime("%Y-%m-%d") if creation else None,
            "expiration_date": expiration.strftime("%Y-%m-%d") if expiration else None,
            "registrar": str(registrar).strip() if registrar else None,
            "age_days": age_days,
            "age_text": age_text,
            "is_recently_registered": is_recently_registered,
            "warning": warning,
            "status": "active" if creation else "no_creation_date",
        }
    except Exception as e:
        logger.debug(f"Socket WHOIS lookup failed for {domain}: {e}")
        return None


def _query_whois_rdap(domain: str) -> Optional[dict]:
    """Fallback query via ICANN RDAP REST API over standard HTTPS."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        with httpx.Client(timeout=3.0, follow_redirects=True) as client:
            resp = client.get(url, headers={"Accept": "application/rdap+json"})
            if resp.status_code != 200:
                return None
            data = resp.json()

        creation = None
        expiration = None
        for event in data.get("events", []):
            action = event.get("eventAction")
            date_str = event.get("eventDate")
            if action == "registration":
                creation = _normalize_datetime(date_str)
            elif action == "expiration":
                expiration = _normalize_datetime(date_str)

        registrar = None
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for entry in vcard[1]:
                        if entry and entry[0] == "fn":
                            registrar = entry[3]
                            break
                if not registrar and "handle" in entity:
                    registrar = entity.get("handle")

        now = datetime.now(timezone.utc)
        age_days = None
        age_text = None
        is_recently_registered = False
        warning = None

        if creation:
            age_days = max(0, (now - creation).days)
            age_text = _format_age(age_days)
            if age_days <= 30:
                is_recently_registered = True
                warning = "⚠ Recently registered domain"

        return {
            "domain": domain,
            "creation_date": creation.strftime("%Y-%m-%d") if creation else None,
            "expiration_date": expiration.strftime("%Y-%m-%d") if expiration else None,
            "registrar": str(registrar).strip() if registrar else None,
            "age_days": age_days,
            "age_text": age_text,
            "is_recently_registered": is_recently_registered,
            "warning": warning,
            "status": "active" if creation else "no_creation_date",
        }
    except Exception as e:
        logger.debug(f"RDAP lookup failed for {domain}: {e}")
        return None


def _query_dns(hostname: str) -> dict:
    """Resolve A, MX, and NS records with strict timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    a_records: List[str] = []
    mx_records: List[str] = []
    nameservers: List[str] = []
    status = "resolved"

    # 1. Query A records
    try:
        answers = resolver.resolve(hostname, "A")
        a_records = [r.to_text() for r in answers]
    except dns.resolver.NXDOMAIN:
        status = "nxdomain"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        status = "no_a_records"
    except dns.exception.Timeout:
        status = "timeout"
    except Exception:
        status = "error"

    # 2. Query MX records (only if domain resolved or no_a_records)
    if status in ("resolved", "no_a_records"):
        try:
            answers = resolver.resolve(hostname, "MX")
            mx_records = [r.exchange.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

    # 3. Query Nameservers (NS)
    if status in ("resolved", "no_a_records"):
        try:
            answers = resolver.resolve(hostname, "NS")
            nameservers = [r.target.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

    return {
        "a_records": a_records,
        "mx_records": mx_records,
        "nameservers": nameservers,
        "status": status,
    }


def get_domain_intelligence(domain_or_url: str) -> dict:
    """
    Perform domain-level intelligence and infrastructure analysis:
    - Domain age & creation date
    - Registrar & expiration date
    - Recently registered domain detection (<= 30 days)
    - DNS resolution status, A records, MX records, Nameservers
    - Safe handling for raw IP hosts and localhost
    - In-memory 1-hour TTL cache
    """
    if not domain_or_url or not isinstance(domain_or_url, str):
        return {
            "domain": "",
            "is_ip": False,
            "whois": {"status": "invalid_input"},
            "dns": {"status": "invalid_input"},
        }

    # Normalize input
    target = domain_or_url.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        norm = normalize_url(f"https://{target}")
    else:
        norm = normalize_url(target)

    hostname = norm.get("hostname", "")
    registered_domain = norm.get("registered_domain", "") or hostname
    is_ip = norm.get("is_ip", False)

    # 1. Handle Raw IP hosts
    if is_ip or not registered_domain:
        return {
            "domain": hostname or target,
            "is_ip": True,
            "whois": {
                "domain": hostname,
                "creation_date": None,
                "expiration_date": None,
                "registrar": None,
                "age_days": None,
                "age_text": None,
                "is_recently_registered": False,
                "warning": None,
                "status": "na_ip_host",
            },
            "dns": {
                "a_records": [hostname] if is_ip else [],
                "mx_records": [],
                "nameservers": [],
                "status": "direct_ip" if is_ip else "unknown",
            },
        }

    # 2. Check Cache
    cache_key = registered_domain.lower()
    now_ts = time.time()
    if cache_key in _DOMAIN_INTEL_CACHE:
        cached_ts, cached_data = _DOMAIN_INTEL_CACHE[cache_key]
        if now_ts - cached_ts < CACHE_TTL_SECONDS:
            return cached_data

    # 3. Perform DNS Analysis
    dns_data = _query_dns(hostname)

    # 4. Perform WHOIS Analysis (Socket -> RDAP fallback)
    whois_data = _query_whois_socket(registered_domain)
    if not whois_data or whois_data.get("status") == "no_creation_date":
        rdap_data = _query_whois_rdap(registered_domain)
        if rdap_data and rdap_data.get("creation_date"):
            whois_data = rdap_data

    if not whois_data:
        whois_data = {
            "domain": registered_domain,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "age_days": None,
            "age_text": None,
            "is_recently_registered": False,
            "warning": None,
            "status": "lookup_failed",
        }

    result = {
        "domain": registered_domain,
        "is_ip": False,
        "whois": whois_data,
        "dns": dns_data,
    }

    # Store in Cache
    _DOMAIN_INTEL_CACHE[cache_key] = (now_ts, result)
    return result


def evaluate_domain_risk_signal(intel: dict) -> dict:
    """
    Evaluate domain intelligence signals into risk scores and reasons.
    Note: As per requirements, a newly registered domain isn't automatically
    malicious; it is one signal, not a verdict (+20 penalty, moderate severity).
    """
    penalty = 0
    reasons = []
    indicators = []
    detected = []

    whois_info = intel.get("whois", {})
    dns_info = intel.get("dns", {})

    # Signal 1: Recently Registered Domain (<= 30 days)
    if whois_info.get("is_recently_registered"):
        age_text = whois_info.get("age_text", "recently")
        age_days = whois_info.get("age_days", 0)
        penalty += 20
        detected.append(f"Recently registered domain ({age_text} old)")
        indicators.append({
            "name": "recently_registered_domain",
            "severity": "medium",
            "weight": 20,
            "detail": f"Domain registered {age_text} ago ({age_days} days)."
        })
        reasons.append(
            f"The domain was registered recently ({age_text} ago). Newly created domains "
            "are statistically correlated with disposable phishing and quishing campaigns."
        )

    # Signal 2: DNS NXDOMAIN (Domain does not exist or has been taken down)
    if dns_info.get("status") == "nxdomain" and not intel.get("is_ip"):
        penalty += 25
        detected.append("Unresolved domain (NXDOMAIN)")
        indicators.append({
            "name": "unresolved_domain",
            "severity": "medium",
            "weight": 25,
            "detail": "Domain does not resolve to active DNS records."
        })
        reasons.append("The domain does not resolve to active DNS records (NXDOMAIN).")

    return {
        "penalty": penalty,
        "reasons": reasons,
        "indicators": indicators,
        "detected": detected,
    }


def calculate_domain_signals_score(domain_intel: dict, tls_analysis: dict, is_trusted: bool = False) -> dict:
    """
    Computes a dedicated 0-100 Domain Signals Score by assessing infrastructure health:
    - Domain Age & Registration Recency
    - DNS Resolution Status & Record Coverage
    - TLS/SSL Transport Security, Hostname Matching & Certificate Validity
    """
    if is_trusted:
        return {
            "score": 0,
            "level": "LOW",
            "breakdown": {"whois": 0, "dns": 0, "tls": 0},
            "reasons": ["Reputable authority infrastructure verified."]
        }

    whois_info = domain_intel.get("whois", {}) if domain_intel else {}
    dns_info = domain_intel.get("dns", {}) if domain_intel else {}
    tls_info = tls_analysis or {}
    is_ip = domain_intel.get("is_ip", False) if domain_intel else False

    reasons = []
    whois_score = 0
    dns_score = 0
    tls_score = 0

    # 1. WHOIS Evaluation
    if is_ip:
        whois_score += 35
        reasons.append("Autonomous system / Raw IP hosting without registered domain pedigree.")
    elif whois_info.get("is_recently_registered"):
        whois_score += 45
        age_text = whois_info.get("age_text", "recently")
        reasons.append(f"Recently registered domain ({age_text} old).")
    elif whois_info.get("age_days") is not None and whois_info.get("age_days") < 90:
        whois_score += 25
        reasons.append("Young domain registration (<90 days old).")

    # 2. DNS Infrastructure Evaluation
    if not is_ip:
        if dns_info.get("status") == "nxdomain":
            dns_score += 50
            reasons.append("Non-existent domain (NXDOMAIN) or suspended infrastructure.")
        elif not dns_info.get("a_records") and dns_info.get("status") != "resolved":
            dns_score += 25
            reasons.append("Missing or incomplete IPv4 A-records.")
        elif not dns_info.get("mx_records"):
            dns_score += 10

    # 3. TLS Transport Security Evaluation
    if not tls_info.get("has_https"):
        tls_score += 35
        reasons.append("Missing HTTPS transport encryption (plaintext HTTP).")
    else:
        if not tls_info.get("certificate_valid"):
            status = tls_info.get("certificate_status", "invalid")
            tls_score += 45
            reasons.append(f"Invalid TLS certificate status: {status}.")
        elif not tls_info.get("hostname_match"):
            tls_score += 40
            reasons.append("TLS certificate Subject CN / SAN mismatch.")
        elif tls_info.get("expiry_days") is not None and tls_info.get("expiry_days") <= 14:
            tls_score += 15
            reasons.append("TLS certificate expiring in <= 14 days.")

    raw_score = whois_score + dns_score + tls_score
    if is_ip and not tls_info.get("has_https"):
        raw_score = max(raw_score, 65)

    score = min(max(raw_score, 0), 100)
    level = "HIGH" if score >= 70 else ("MEDIUM" if score >= 35 else "LOW")

    return {
        "score": score,
        "level": level,
        "breakdown": {
            "whois": min(whois_score, 100),
            "dns": min(dns_score, 100),
            "tls": min(tls_score, 100)
        },
        "reasons": reasons
    }

