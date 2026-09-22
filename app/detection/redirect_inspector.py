import time
import httpx
import logging
from typing import Optional, Dict

logger = logging.getLogger("redirect_inspector")

# In-memory cache for safe redirect inspections
_REDIRECT_CACHE: Dict[str, tuple[float, dict]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


def inspect_shortener_redirect(url: str) -> dict:
    """
    Safely inspect a shortened URL for its target destination without downloading
    untrusted payloads or executing client-side scripts.
    Uses HTTP HEAD with follow_redirects=False to read the Location header.
    """
    if not url or not isinstance(url, str):
        return {
            "has_redirect": False,
            "redirect_target": None,
            "status_code": None,
        }

    clean_url = url.strip()
    cache_key = clean_url.lower()
    now_ts = time.time()

    if cache_key in _REDIRECT_CACHE:
        cached_ts, cached_data = _REDIRECT_CACHE[cache_key]
        if now_ts - cached_ts < CACHE_TTL_SECONDS:
            return cached_data

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 QRQuishingInspector/2.0"
    }

    try:
        with httpx.Client(timeout=2.5, follow_redirects=False, verify=False) as client:
            resp = client.head(clean_url, headers=headers)
            # If server forbids HEAD (e.g. 405 Method Not Allowed), retry with GET streaming (no body read)
            if resp.status_code == 405:
                with client.stream("GET", clean_url, headers=headers) as stream_resp:
                    status_code = stream_resp.status_code
                    location = stream_resp.headers.get("Location")
            else:
                status_code = resp.status_code
                location = resp.headers.get("Location")

            is_redirect = status_code in (301, 302, 303, 307, 308) and bool(location)
            result = {
                "has_redirect": is_redirect,
                "redirect_target": location if is_redirect else None,
                "status_code": status_code,
            }
    except Exception as e:
        logger.debug(f"Redirect inspection non-fatal error for {clean_url}: {e}")
        result = {
            "has_redirect": False,
            "redirect_target": None,
            "status_code": None,
            "error": str(e),
        }

    _REDIRECT_CACHE[cache_key] = (now_ts, result)
    return result
