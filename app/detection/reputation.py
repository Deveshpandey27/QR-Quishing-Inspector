# Authoritative, widely recognized domains for false-positive suppression
TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "gmail.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "wikipedia.org",
    "paypal.com",
    "dropbox.com",
    "netflix.com",
    "spotify.com",
    "adobe.com",
    "yahoo.com",
    "reddit.com",
    "stackoverflow.com",
}

# Major brands frequently targeted in phishing/quishing impersonation attacks
HIGH_TARGET_BRANDS = {
    "paypal": "PayPal",
    "google": "Google",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "netflix": "Netflix",
    "amazon": "Amazon",
    "chase": "Chase Bank",
    "wellsfargo": "Wells Fargo",
    "bankofamerica": "Bank of America",
    "binance": "Binance",
    "coinbase": "Coinbase",
    "facebook": "Facebook",
    "meta": "Meta",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "dhl": "DHL",
    "fedex": "FedEx",
    "usps": "USPS",
}


def is_trusted_domain(registered_domain: str, hostname: str = None) -> bool:
    if not registered_domain:
        return False
    clean_domain = registered_domain.lower().strip()
    if clean_domain in TRUSTED_DOMAINS:
        return True
    if hostname:
        clean_host = hostname.lower().strip()
        for td in TRUSTED_DOMAINS:
            if clean_host == td or clean_host.endswith("." + td):
                return True
    return False
