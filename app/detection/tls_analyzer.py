import time
import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.detection.normalizer import normalize_url

logger = logging.getLogger("tls_analyzer")

# In-memory TTL cache for TLS inspection results
# Cache format: {cache_key: (timestamp, data_dict)}
_TLS_CACHE: Dict[str, tuple[float, dict]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


def _parse_cert_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def inspect_tls(url_or_host: str) -> dict:
    """
    Perform deep SSL/TLS security analysis:
    - HTTPS enforcement check
    - TLS certificate validity & verification
    - Hostname match (CN & Subject Alternative Names)
    - Expiration date & days remaining calculation
    - Issuer identification
    - 1-hour in-memory TTL caching
    """
    if not url_or_host or not isinstance(url_or_host, str):
        return {
            "has_https": False,
            "certificate_valid": False,
            "certificate_status": "invalid_input",
            "hostname_match": False,
            "issuer": None,
            "subject_cn": None,
            "issued_date": None,
            "expiration_date": None,
            "expiry_days": None,
            "expiry_text": "N/A",
            "warning": "No URL provided for TLS analysis.",
            "raw_error": None,
        }

    target = url_or_host.strip()
    norm = normalize_url(target)
    scheme = norm.get("scheme", "http")
    hostname = norm.get("hostname", "")
    port = norm.get("port")
    is_ip = norm.get("is_ip", False)

    # 1. Non-HTTPS / Plain HTTP protocol
    if scheme != "https":
        return {
            "has_https": False,
            "certificate_valid": False,
            "certificate_status": "missing_https",
            "hostname_match": False,
            "issuer": None,
            "subject_cn": None,
            "issued_date": None,
            "expiration_date": None,
            "expiry_days": None,
            "expiry_text": "N/A (HTTP Plaintext)",
            "warning": "URL uses unencrypted HTTP protocol without TLS encryption.",
            "raw_error": None,
        }

    target_port = port if port is not None else 443

    # 2. Check Cache
    cache_key = f"{hostname.lower()}:{target_port}"
    now_ts = time.time()
    if cache_key in _TLS_CACHE:
        cached_ts, cached_data = _TLS_CACHE[cache_key]
        if now_ts - cached_ts < CACHE_TTL_SECONDS:
            return cached_data

    # 3. Perform TLS Handshake & Certificate Probing
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((hostname, target_port), timeout=3.0)
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

        # Parse Certificate fields
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        subject_cn = subject_dict.get("commonName")

        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

        not_before = _parse_cert_date(cert.get("notBefore"))
        not_after = _parse_cert_date(cert.get("notAfter"))

        now_utc = datetime.now(timezone.utc)
        expiry_days = None
        expiry_text = "Unknown"
        is_expired = False
        warning = None

        if not_after:
            diff_seconds = (not_after - now_utc).total_seconds()
            if diff_seconds <= 0:
                is_expired = True
                expiry_days = 0
                expiry_text = "Expired"
                warning = "TLS certificate has expired."
            else:
                expiry_days = int(diff_seconds // 86400)
                expiry_text = f"{expiry_days} days"
                if expiry_days <= 14:
                    warning = f"TLS certificate expires soon ({expiry_days} days)."

        result = {
            "has_https": True,
            "certificate_valid": not is_expired,
            "certificate_status": "valid" if not is_expired else "expired",
            "hostname_match": True,  # wrap_socket enforces SNI and SAN/CN hostname validation
            "issuer": issuer,
            "subject_cn": subject_cn,
            "issued_date": not_before.strftime("%Y-%m-%d") if not_before else None,
            "expiration_date": not_after.strftime("%Y-%m-%d") if not_after else None,
            "expiry_days": expiry_days,
            "expiry_text": expiry_text,
            "warning": warning,
            "raw_error": None,
        }

    except ssl.SSLCertVerificationError as e:
        err_msg = str(e).lower()
        if "expired" in err_msg:
            status = "expired"
            warn = "TLS certificate has expired."
        elif "self-signed" in err_msg or "self signed" in err_msg:
            status = "self_signed"
            warn = "TLS certificate is self-signed and not trusted by recognized Certificate Authorities."
        elif "hostname" in err_msg and ("mismatch" in err_msg or "doesn't match" in err_msg):
            status = "hostname_mismatch"
            warn = "Certificate hostname does not match destination hostname."
        else:
            status = "invalid"
            warn = f"TLS certificate verification failed: {e.verify_message}"

        result = {
            "has_https": True,
            "certificate_valid": False,
            "certificate_status": status,
            "hostname_match": False if status == "hostname_mismatch" else True,
            "issuer": None,
            "subject_cn": None,
            "issued_date": None,
            "expiration_date": None,
            "expiry_days": None,
            "expiry_text": "Invalid Certificate",
            "warning": warn,
            "raw_error": str(e),
        }

    except ssl.CertificateError as e:
        result = {
            "has_https": True,
            "certificate_valid": False,
            "certificate_status": "hostname_mismatch",
            "hostname_match": False,
            "issuer": None,
            "subject_cn": None,
            "issued_date": None,
            "expiration_date": None,
            "expiry_days": None,
            "expiry_text": "Hostname Mismatch",
            "warning": "Certificate Common Name/SAN does not match destination domain.",
            "raw_error": str(e),
        }

    except (socket.timeout, TimeoutError):
        result = {
            "has_https": True,
            "certificate_valid": False,
            "certificate_status": "timeout",
            "hostname_match": False,
            "issuer": None,
            "subject_cn": None,
            "issued_date": None,
            "expiration_date": None,
            "expiry_days": None,
            "expiry_text": "Timeout",
            "warning": "TLS connection timed out after 3.0s.",
            "raw_error": "Connection timed out",
        }

    except Exception as e:
        result = {
            "has_https": True,
            "certificate_valid": False,
            "certificate_status": "connection_failed",
            "hostname_match": False,
            "issuer": None,
            "subject_cn": None,
            "issued_date": None,
            "expiration_date": None,
            "expiry_days": None,
            "expiry_text": "Connection Failed",
            "warning": f"Could not establish TLS connection: {str(e)}",
            "raw_error": str(e),
        }

    _TLS_CACHE[cache_key] = (now_ts, result)
    return result


def evaluate_tls_risk_signal(tls_data: dict) -> dict:
    """
    Evaluate TLS data into heuristic security signals.
    Important Security Rule:
    A valid HTTPS certificate does NOT prove a website is safe. Phishing sites
    frequently use valid certificates (e.g. Let's Encrypt).
    Therefore, valid certificates do NOT reduce phishing scores to 0.
    However, invalid, expired, self-signed, or mismatched certificates add +25 penalty.
    """
    penalty = 0
    reasons = []
    indicators = []
    detected = []

    # If scheme was HTTPS but certificate is invalid/expired/mismatched
    if tls_data.get("has_https"):
        if not tls_data.get("certificate_valid") and tls_data.get("certificate_status") != "connection_failed":
            status = tls_data.get("certificate_status", "invalid")
            penalty += 25
            status_label = status.replace("_", " ").title()
            detected.append(f"Invalid TLS certificate ({status_label})")
            indicators.append({
                "name": "invalid_tls_certificate",
                "severity": "high",
                "weight": 25,
                "detail": tls_data.get("warning") or f"Certificate status: {status}"
            })
            reasons.append(
                f"TLS certificate validation failed ({status_label}): {tls_data.get('warning', 'Untrusted or expired certificate')}."
            )

    return {
        "penalty": penalty,
        "reasons": reasons,
        "indicators": indicators,
        "detected": detected,
    }
