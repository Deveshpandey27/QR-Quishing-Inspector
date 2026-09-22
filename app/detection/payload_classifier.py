import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

URL_REGEX = re.compile(
    r"(?:https?://|www\.)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*(?::\d+)?(?:/[^\s<>\"']*)*|"
    r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>\"']*)?",
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)

PHONE_REGEX = re.compile(
    r"^(?:\+?\d{1,4}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?[\d\s.-]{6,14}$"
)


def extract_embedded_urls(text: str) -> List[str]:
    """Finds any web URLs contained within an arbitrary text block."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    urls = []
    for m in matches:
        m_clean = m.strip('.,;:()[]{}<>"\'')
        if m_clean and ("." in m_clean or m_clean.startswith("http")) and m_clean not in urls:
            urls.append(m_clean)
    return urls


def _parse_wifi(raw: str) -> Dict[str, Any]:
    """
    Parses standard MeCard/ZXing Wi-Fi format:
    WIFI:T:WPA;S=HomeNetwork;P=password;H:false;;
    """
    # Remove leading WIFI:
    body = raw[5:]
    if body.endswith(";;"):
        body = body[:-2]
    elif body.endswith(";"):
        body = body[:-1]

    parts = body.split(";")
    ssid = ""
    auth_type = "nopass"
    password = ""
    hidden = False

    for part in parts:
        if not part:
            continue
        # Format can be KEY:VAL or KEY=VAL
        delim = ":" if ":" in part else ("=" if "=" in part else None)
        if not delim:
            continue
        k, v = part.split(delim, 1)
        k = k.strip().upper()
        v = v.strip()
        if k == "S":
            ssid = v
        elif k == "T":
            auth_type = v.upper() or "nopass"
        elif k == "P":
            password = v
        elif k == "H":
            hidden = v.lower() in ("true", "1", "yes")

    # Mask password for display
    masked_pw = "•" * len(password) if password else "(None)"

    # Warnings & risk assessment
    is_open = auth_type.lower() in ("nopass", "none", "open") or not password
    is_weak = auth_type.lower() == "wep"

    reasons = [
        "This QR code contains network credentials.",
        f"Network SSID (Name): {ssid or '(Hidden / Unnamed)'}",
        f"Security Protocol: {auth_type}"
    ]
    if is_open:
        reasons.append("Unencrypted (Open) Wi-Fi network detected. Susceptible to Evil Twin / Man-in-the-Middle attacks.")
    if is_weak:
        reasons.append("Obsolete WEP encryption detected. Vulnerable to fast key recovery.")

    score = 50 if is_open else (65 if is_weak else 40)
    risk_level = "MEDIUM" if (is_open or is_weak) else "LOW"
    status = "suspicious" if (is_open or is_weak) else "safe"

    return {
        "content_type": "wifi",
        "type_label": "Wi-Fi configuration",
        "security_warning": "This QR code contains network credentials.",
        "ssid": ssid,
        "auth_type": auth_type,
        "password": password,
        "password_masked": masked_pw,
        "masked_password": masked_pw,
        "is_sensitive": True,
        "is_hidden": hidden,
        "is_open": is_open,
        "is_weak": is_weak,
        "score": score,
        "risk_level": risk_level,
        "status": status,
        "reasons": reasons,
        "recommendation": "Verify that this is your intended Wi-Fi network. Do not connect to unknown public or rogue hotspots."
    }


def _parse_email(raw: str) -> Dict[str, Any]:
    """Parses mailto: or MATMSG: email payloads."""
    recipient = ""
    subject = ""
    body = ""

    if raw.lower().startswith("mailto:"):
        parsed = urllib.parse.urlparse(raw)
        recipient = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)
        subject = query_params.get("subject", [""])[0]
        body = query_params.get("body", [""])[0]
    elif raw.upper().startswith("MATMSG:"):
        # Format MATMSG:TO:usr@domain.com;SUB:Subject;BODY:Body;;
        content = raw[7:]
        to_m = re.search(r"TO:(.*?);", content, re.IGNORECASE)
        sub_m = re.search(r"SUB:(.*?);", content, re.IGNORECASE)
        body_m = re.search(r"BODY:(.*?);;", content, re.IGNORECASE) or re.search(r"BODY:(.*?);", content, re.IGNORECASE)
        if to_m:
            recipient = to_m.group(1).strip()
        if sub_m:
            subject = sub_m.group(1).strip()
        if body_m:
            body = body_m.group(1).strip()
    else:
        recipient = raw.strip()

    embedded_urls = extract_embedded_urls(f"{subject} {body}")
    is_phishing_lure = any(k in f"{subject} {body}".lower() for k in ["urgent", "verify", "suspend", "password", "reset", "wire", "invoice", "bank", "account"])

    reasons = [
        f"Email recipient: {recipient or 'Unspecified'}"
    ]
    if subject:
        reasons.append(f"Pre-filled subject: '{subject}'")
    if embedded_urls:
        reasons.append(f"Embedded URL link detected in email body: {embedded_urls[0]}")
    if is_phishing_lure:
        reasons.append("High-urgency phishing or credential lure keywords detected in email content.")

    score = 75 if (embedded_urls and is_phishing_lure) else (55 if (embedded_urls or is_phishing_lure) else 20)
    risk_level = "HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW")
    status = "dangerous" if score >= 70 else ("suspicious" if score >= 40 else "safe")

    warning = "⚠ Potential Phishing Email Vector" if is_phishing_lure else (
        "⚠ Email contains embedded destination link" if embedded_urls else "QR code drafts an outgoing email."
    )

    return {
        "content_type": "email",
        "type_label": "Email",
        "security_warning": warning,
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "embedded_urls": embedded_urls,
        "is_phishing_lure": is_phishing_lure,
        "score": score,
        "risk_level": risk_level,
        "status": status,
        "reasons": reasons,
        "recommendation": "Review recipient and message contents carefully before sending. Do not follow unverified links in email bodies."
    }


def _parse_phone(raw: str) -> Dict[str, Any]:
    """Parses tel: and phone number payloads."""
    clean_num = raw
    if clean_num.lower().startswith("tel:"):
        clean_num = clean_num[4:]
    clean_num = clean_num.strip()

    digits_only = re.sub(r"\D", "", clean_num)
    is_premium = any(digits_only.startswith(p) for p in ["1900", "900", "0900", "976"])

    reasons = [
        f"Telephone dial target: {clean_num}"
    ]
    if is_premium:
        reasons.append("Premium-rate number pattern detected (possible toll-fraud or unauthorized billable call).")

    score = 80 if is_premium else 15
    risk_level = "HIGH" if is_premium else "LOW"
    status = "dangerous" if is_premium else "safe"
    warning = "⚠ Toll Fraud / Premium Rate Number Warning" if is_premium else "QR code prompts phone dialer."

    return {
        "content_type": "phone",
        "type_label": "Phone number",
        "security_warning": warning,
        "phone_number": clean_num,
        "digits_only": digits_only,
        "is_premium": is_premium,
        "score": score,
        "risk_level": risk_level,
        "status": status,
        "reasons": reasons,
        "recommendation": "Confirm target identity before dialing to avoid toll-fraud or voice-phishing (vishing) traps."
    }


def _parse_vcard(raw: str) -> Dict[str, Any]:
    """Parses vCard / contact card payloads."""
    fn = ""
    org = ""
    tel = ""
    email = ""
    url = ""
    title = ""

    lines = raw.splitlines()
    for line in lines:
        line_clean = line.strip()
        if ":" not in line_clean:
            continue
        k, v = line_clean.split(":", 1)
        k_upper = k.strip().upper()
        v_val = v.strip()
        if k_upper == "FN":
            fn = v_val
        elif k_upper == "ORG":
            org = v_val
        elif k_upper.startswith("TEL"):
            tel = v_val
        elif k_upper.startswith("EMAIL"):
            email = v_val
        elif k_upper.startswith("URL"):
            url = v_val
        elif k_upper == "TITLE":
            title = v_val

    # Also check MECARD format (MECARD:N:Doe,John;TEL:555;EMAIL:...;)
    if not fn and raw.upper().startswith("MECARD:"):
        content = raw[7:]
        n_m = re.search(r"N:(.*?);", content, re.IGNORECASE)
        tel_m = re.search(r"TEL:(.*?);", content, re.IGNORECASE)
        email_m = re.search(r"EMAIL:(.*?);", content, re.IGNORECASE)
        url_m = re.search(r"URL:(.*?);", content, re.IGNORECASE)
        if n_m:
            fn = n_m.group(1).replace(",", " ").strip()
        if tel_m:
            tel = tel_m.group(1).strip()
        if email_m:
            email = email_m.group(1).strip()
        if url_m:
            url = url_m.group(1).strip()

    embedded_urls = []
    if url:
        embedded_urls.append(url)
    all_extracted = extract_embedded_urls(raw)
    for eu in all_extracted:
        if eu not in embedded_urls:
            embedded_urls.append(eu)

    reasons = [
        f"Contact Name: {fn or 'Unnamed'}"
    ]
    if org:
        reasons.append(f"Organization: {org}")
    if tel:
        reasons.append(f"Phone: {tel}")
    if email:
        reasons.append(f"Email: {email}")
    if embedded_urls:
        reasons.append(f"Contact card embeds web link: {embedded_urls[0]} (quishing vector)")

    score = 65 if embedded_urls else 15
    risk_level = "MEDIUM" if embedded_urls else "LOW"
    status = "suspicious" if embedded_urls else "safe"
    warning = "⚠ Contact Card Contains Embedded Web Link (Quishing Vector)" if embedded_urls else "QR code contains contact information."

    return {
        "content_type": "vcard",
        "type_label": "vCard/contact",
        "security_warning": warning,
        "name": fn,
        "organization": org,
        "org": org,
        "phone": tel,
        "email": email,
        "url": url,
        "title": title,
        "embedded_urls": embedded_urls,
        "score": score,
        "risk_level": risk_level,
        "status": status,
        "reasons": reasons,
        "recommendation": "Inspect any embedded website links before visiting. Do not import unverified contacts."
    }


def _parse_plain_text(raw: str) -> Dict[str, Any]:
    """Parses plain text payloads, scanning for embedded URLs, scripts, and credentials."""
    embedded_urls = extract_embedded_urls(raw)
    raw_lower = raw.lower()

    # Check for script or command injection patterns
    has_injection = any(p in raw_lower for p in ["<script", "javascript:", "powershell", "cmd.exe", "bash -c", "curl ", "wget "])
    has_credentials = any(k in raw_lower for k in ["password:", "passcode:", "otp:", "token:", "secret key:", "private key:"])

    reasons = [
        f"Payload length: {len(raw)} characters"
    ]
    if embedded_urls:
        reasons.append(f"Embedded web destination detected: {embedded_urls[0]}")
    if has_injection:
        reasons.append("Malicious script / shell command execution syntax detected.")
    if has_credentials:
        reasons.append("Sensitive authentication token or credential pattern detected.")

    if has_injection:
        score = 85
        risk_level = "HIGH"
        status = "dangerous"
        warning = "⚠ Malicious Code / Command Injection Payload Detected"
    elif embedded_urls:
        score = 60
        risk_level = "MEDIUM"
        status = "suspicious"
        warning = "⚠ Plain Text Contains Embedded Web Link"
    elif has_credentials:
        score = 55
        risk_level = "MEDIUM"
        status = "suspicious"
        warning = "⚠ Plain Text Exposes Authentication Credentials"
    else:
        score = 10
        risk_level = "LOW"
        status = "safe"
        warning = "QR code contains plain text."

    return {
        "content_type": "text",
        "type_label": "Plain text",
        "security_warning": warning,
        "text_content": raw,
        "length": len(raw),
        "embedded_urls": embedded_urls,
        "has_injection": has_injection,
        "has_credentials": has_credentials,
        "score": score,
        "risk_level": risk_level,
        "status": status,
        "reasons": reasons,
        "recommendation": "Do not execute unverified shell commands or paste sensitive authentication tokens into untrusted apps."
    }


def classify_qr_payload(raw_text: str) -> Dict[str, Any]:
    """
    Classifies raw QR payload into one of 6 types:
    1. URL
    2. Plain text
    3. Email
    4. Phone number
    5. Wi-Fi configuration
    6. vCard/contact
    """
    if not raw_text:
        return _parse_plain_text("")

    text_stripped = raw_text.strip()
    text_upper = text_stripped.upper()

    # 1. Wi-Fi Configuration
    if text_upper.startswith("WIFI:"):
        return _parse_wifi(text_stripped)

    # 2. Email
    if text_upper.startswith("MAILTO:") or text_upper.startswith("MATMSG:") or text_upper.startswith("SMTP:"):
        return _parse_email(text_stripped)
    if EMAIL_REGEX.match(text_stripped):
        return _parse_email(text_stripped)

    # 3. Phone number
    if text_upper.startswith("TEL:"):
        return _parse_phone(text_stripped)
    # Check pure phone number (requires at least 7 digits)
    digits = re.sub(r"\D", "", text_stripped)
    if len(digits) >= 7 and PHONE_REGEX.match(text_stripped) and not any(c in text_stripped for c in ["/", ":", "?", "&", "="]):
        return _parse_phone(text_stripped)

    # 4. vCard / Contact
    if text_upper.startswith("BEGIN:VCARD") or text_upper.startswith("MECARD:"):
        return _parse_vcard(text_stripped)

    # 5. URL
    if text_stripped.lower().startswith(("http://", "https://", "ftp://")):
        return {
            "content_type": "url",
            "type_label": "URL",
            "security_warning": "QR code contains web destination URL.",
            "url": text_stripped,
            "embedded_urls": [text_stripped],
            "score": 0,
            "risk_level": "LOW",
            "status": "safe",
            "reasons": ["Standard web destination format."],
            "recommendation": "Analyze with full multi-engine quishing inspector."
        }

    # Check if string matches domain URL format (e.g. google.com, bit.ly/abc, example.xyz/login)
    domain_match = re.match(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?:/[^\s]*)?$", text_stripped)
    if domain_match and "." in text_stripped and not " " in text_stripped and len(text_stripped.split(".")[0]) > 1:
        return {
            "content_type": "url",
            "type_label": "URL",
            "security_warning": "QR code contains web destination URL.",
            "url": f"https://{text_stripped}",
            "embedded_urls": [text_stripped],
            "score": 0,
            "risk_level": "LOW",
            "status": "safe",
            "reasons": ["Standard web destination format without explicit protocol."],
            "recommendation": "Analyze with full multi-engine quishing inspector."
        }

    # 6. Plain Text (Default fallback)
    return _parse_plain_text(text_stripped)


def sanitize_payload_for_storage(payload_str: str) -> str:
    """
    Redacts sensitive credentials (such as Wi-Fi passwords) so they are not
    stored in audit logs or history on disk:
    'Be careful not to store sensitive QR payloads unnecessarily.'
    """
    if not payload_str:
        return payload_str

    if payload_str.strip().upper().startswith("WIFI:"):
        # Replace P=...; with P=********;
        sanitized = re.sub(r"(P[:=])(.*?)(;)", r"\g<1>********\g<3>", payload_str, flags=re.IGNORECASE)
        return sanitized

    return payload_str


classify_payload = classify_qr_payload
