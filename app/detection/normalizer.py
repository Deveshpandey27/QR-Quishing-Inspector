import ipaddress
import re
from urllib.parse import urlparse, urlunparse


# Common URL shorteners frequently abused in Quishing to conceal malicious destinations
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "shorturl.at",
    "rebrand.ly",
    "bl.ink",
    "rb.gy",
    "t.ly",
    "v.gd",
    "qr.de",
    "qr.net",
    "q-r.to",
    "s.id",
    "tr.ee",
    "trib.al",
}

# Two-part second-level domain suffixes (e.g. .co.uk, .com.au, .gov.in)
TWO_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in", "ind.in",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.za", "org.za",
    "com.br", "net.br", "org.br",
    "com.sg", "edu.sg",
}


def normalize_url(raw_url: str) -> dict:
    """
    Clean, validate, and normalize a URL for cybersecurity inspection.

    Handles:
    - Trimming leading/trailing whitespace and control characters.
    - Defaulting to https:// if no protocol scheme is supplied.
    - Lowercasing the hostname while preserving path casing.
    - Extracting registered domain, subdomains, and checking for IP addresses.
    - Detecting URL shorteners and Punycode (IDN homograph) attacks.

    Returns:
        dict with normalized_url, parsed components, is_ip, is_shortener, is_punycode.
    """
    if not raw_url:
        return {
            "valid": False,
            "error": "URL cannot be empty.",
            "url": "",
            "hostname": "",
            "registered_domain": "",
            "subdomains": [],
            "is_ip": False,
            "is_shortener": False,
            "is_punycode": False,
            "port": None,
            "tld": "",
        }

    url = raw_url.strip()

    # Prepend https:// if no scheme is provided
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return {
            "valid": False,
            "error": f"Malformed URL: {exc}",
            "url": raw_url,
            "hostname": "",
            "registered_domain": "",
            "subdomains": [],
            "is_ip": False,
            "is_shortener": False,
            "is_punycode": False,
            "port": None,
            "tld": "",
        }

    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    netloc = parsed.netloc or ""

    # Separate credentials/port if present
    auth = ""
    host_port = netloc
    if "@" in netloc:
        auth, host_port = netloc.split("@", 1)

    port = None
    if ":" in host_port and not host_port.endswith("]"):  # Handle IPv6 [::1]:80
        parts = host_port.rsplit(":", 1)
        raw_host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            raw_host = host_port
    else:
        raw_host = host_port

    hostname = raw_host.strip("[]").lower()

    # Determine if hostname is an IP address
    is_ip = False
    is_hex_ip = False
    is_dword_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        # Check alternative representations: Hex IP (0x...) or DWORD integer IP
        if hostname.startswith("0x") or ".0x" in hostname:
            try:
                parts = hostname.split(".")
                if len(parts) == 1 and hostname.startswith("0x"):
                    int(hostname, 16)
                    is_ip = True
                    is_hex_ip = True
                elif len(parts) == 4:
                    octets = [int(p, 16) if p.startswith("0x") else int(p) for p in parts]
                    if all(0 <= o <= 255 for o in octets):
                        is_ip = True
                        is_hex_ip = True
            except Exception:
                pass
        elif hostname.isdigit() and len(hostname) >= 7:
            try:
                val = int(hostname)
                if 0 <= val <= 4294967295:
                    is_ip = True
                    is_dword_ip = True
            except Exception:
                pass

    # Check for Punycode / IDN homograph attack
    is_punycode = "xn--" in hostname

    # Extract registered domain and subdomains
    registered_domain = hostname
    subdomains = []

    if not is_ip and hostname:
        parts = hostname.split(".")
        if len(parts) >= 2:
            # Check for two-part TLDs (e.g. .co.uk, .com.au)
            two_part_tld = ".".join(parts[-2:])
            if two_part_tld in TWO_PART_TLDS and len(parts) >= 3:
                registered_domain = ".".join(parts[-3:])
                subdomains = parts[:-3]
            else:
                registered_domain = ".".join(parts[-2:])
                subdomains = parts[:-2]
        else:
            registered_domain = hostname
            subdomains = []

    # Check URL shortener
    is_shortener = (hostname in SHORTENER_DOMAINS) or (registered_domain in SHORTENER_DOMAINS)

    # Reconstruct normalized URL with lowercased host and clean formatting
    clean_netloc = hostname
    if port and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        clean_netloc = f"{hostname}:{port}"
    if auth:
        clean_netloc = f"{auth}@{clean_netloc}"

    normalized_url = urlunparse((
        scheme,
        clean_netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    tld = ""
    if not is_ip and "." in registered_domain:
        tld = registered_domain.split(".")[-1].lower()

    return {
        "valid": True,
        "error": None,
        "url": normalized_url,
        "scheme": scheme,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomains": subdomains,
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "port": port,
        "tld": tld,
        "has_auth": bool(auth),
        "is_ip": is_ip,
        "is_hex_ip": is_hex_ip,
        "is_dword_ip": is_dword_ip,
        "is_shortener": is_shortener,
        "is_punycode": is_punycode,
    }
