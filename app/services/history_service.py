import os
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")


def _format_relative_date(timestamp_iso: str) -> str:
    """Calculates relative date label: 'Today', 'Yesterday', or 'MM/DD/YYYY'."""
    try:
        dt = datetime.fromisoformat(timestamp_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        
        # Compare calendar dates in UTC
        today_date = now.date()
        scan_date = dt.date()
        
        diff_days = (today_date - scan_date).days
        if diff_days == 0:
            return "Today"
        elif diff_days == 1:
            return "Yesterday"
        elif diff_days < 7:
            return f"{diff_days} days ago"
        else:
            return scan_date.strftime("%b %d, %Y")
    except Exception:
        return "Recent"


def _build_seed_snapshot(url: str, hostname: str, score: int, risk_level: str, status: str, threat_matches: int = 0) -> dict:
    """Generates a comprehensive analysis snapshot for seed items."""
    is_trusted = risk_level == "LOW"
    return {
        "success": True,
        "url": url,
        "hostname": hostname,
        "score": score,
        "risk_level": risk_level,
        "rule_score": score if risk_level != "LOW" else 0,
        "ml_score": 95 if risk_level == "HIGH" else (50 if risk_level == "MEDIUM" else 0),
        "domain_score": 80 if risk_level == "HIGH" else (40 if risk_level == "MEDIUM" else 0),
        "risk_weights": {"rule": 0.35, "ml": 0.45, "domain": 0.20},
        "status": status,
        "title": "Dangerous QR Destination" if risk_level == "HIGH" else ("Suspicious QR Destination" if risk_level == "MEDIUM" else "Looks Safe"),
        "message": "High quishing risk detected." if risk_level == "HIGH" else ("Caution advised." if risk_level == "MEDIUM" else "Authentic destination."),
        "reasons": [
            f"Historical scan recorded with {risk_level} risk classification.",
            "Reputable destination verified." if is_trusted else "Suspicious characteristics flagged during analysis."
        ],
        "indicators": [
            {"name": "historical_audit", "weight": score, "severity": "high" if risk_level == "HIGH" else ("medium" if risk_level == "MEDIUM" else "low"), "detail": "Audited in scan history"}
        ] if not is_trusted else [],
        "detected": [
            f"Risk score {score}/100"
        ] if not is_trusted else [],
        "is_trusted": is_trusted,
        "is_shortener": "bit.ly" in hostname,
        "is_ip": False,
        "domain_intel": {
            "domain": hostname,
            "is_ip": False,
            "whois": {"age_text": "3 years" if is_trusted else "11 days", "is_recently_registered": risk_level == "HIGH", "registrar": "MarkMonitor" if is_trusted else "NameCheap"},
            "dns": {"status": "resolved", "a_records": ["142.250.190.46"] if is_trusted else ["192.0.2.1"]}
        },
        "tls_analysis": {
            "has_https": True,
            "certificate_valid": True,
            "hostname_match": True,
            "expiry_days": 85 if is_trusted else 12,
            "expiry_text": "85 days remaining" if is_trusted else "12 days remaining"
        },
        "shortener_info": {
            "is_shortener": True,
            "service_name": "bit.ly",
            "warning": "Destination cannot be trusted based only on the visible short URL.",
            "redirect_target": "https://secure-target-portal.com/login"
        } if "bit.ly" in hostname else None,
        "threat_intel": {
            "known_malicious": threat_matches > 0,
            "matches_count": threat_matches,
            "sources_checked": 5,
            "providers": [
                {"name": "URLhaus (abuse.ch)", "checked": True, "matched": threat_matches > 0, "status": "malicious" if threat_matches > 0 else "clean", "details": "Flagged" if threat_matches > 0 else "Clean"},
                {"name": "PhishTank", "checked": True, "matched": threat_matches > 1, "status": "malicious" if threat_matches > 1 else "clean", "details": "Verified" if threat_matches > 1 else "Clean"},
                {"name": "Google Safe Browsing", "checked": False, "matched": False, "status": "unconfigured", "details": "Clean"},
                {"name": "VirusTotal", "checked": False, "matched": False, "status": "unconfigured", "details": "Clean"},
                {"name": "OpenPhish & Quishing IOC Feed", "checked": True, "matched": threat_matches > 2, "status": "malicious" if threat_matches > 2 else "clean", "details": "Indexed" if threat_matches > 2 else "Clean"}
            ],
            "warning_message": "⚠ External intelligence indicates this URL has been reported." if threat_matches > 0 else None,
            "summary_text": f"Threat Intelligence\n\nKnown malicious URL:     {'YES' if threat_matches > 0 else 'NO'}\nThreat database matches: {threat_matches}"
        }
    }


def _get_seed_history() -> List[dict]:
    """Provides seed history matching the prompt's exact specification."""
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    return [
        {
            "id": "scan_seed_1",
            "url": "google.com",
            "hostname": "google.com",
            "display_url": "google.com",
            "score": 0,
            "final_score": 0,
            "risk_level": "LOW",
            "status": "safe",
            "timestamp": now.isoformat(),
            "date_label": "Today",
            "relative_date": "Today",
            "analysis_snapshot": _build_seed_snapshot("https://google.com", "google.com", 0, "LOW", "safe", 0)
        },
        {
            "id": "scan_seed_2",
            "url": "example.xyz",
            "hostname": "example.xyz",
            "display_url": "example.xyz",
            "score": 85,
            "final_score": 85,
            "risk_level": "HIGH",
            "status": "dangerous",
            "timestamp": now.isoformat(),
            "date_label": "Today",
            "relative_date": "Today",
            "analysis_snapshot": _build_seed_snapshot("https://example.xyz", "example.xyz", 85, "HIGH", "dangerous", 2)
        },
        {
            "id": "scan_seed_3",
            "url": "bit.ly/abc123",
            "hostname": "bit.ly",
            "display_url": "bit.ly/abc123",
            "score": 55,
            "final_score": 55,
            "risk_level": "MEDIUM",
            "status": "suspicious",
            "timestamp": yesterday.isoformat(),
            "date_label": "Yesterday",
            "relative_date": "Yesterday",
            "analysis_snapshot": _build_seed_snapshot("https://bit.ly/abc123", "bit.ly", 55, "MEDIUM", "suspicious", 0)
        },
        {
            "id": "scan_seed_4",
            "url": "bank-login.xyz",
            "hostname": "bank-login.xyz",
            "display_url": "bank-login.xyz",
            "score": 92,
            "final_score": 92,
            "risk_level": "HIGH",
            "status": "dangerous",
            "timestamp": yesterday.isoformat(),
            "date_label": "Yesterday",
            "relative_date": "Yesterday",
            "analysis_snapshot": _build_seed_snapshot("https://bank-login.xyz", "bank-login.xyz", 92, "HIGH", "dangerous", 3)
        }
    ]


class ScanHistoryService:
    def __init__(self):
        self._history: List[dict] = []
        self._load_from_disk()

    def _load_from_disk(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    self._history = json.load(f)
                    return
            except Exception:
                pass
        
        # Initialize with seed data
        self._history = _get_seed_history()
        self._save_to_disk()

    def _save_to_disk(self):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self._history, f, indent=2)
        except Exception:
            pass

    def get_history(self, limit: int = 50, risk_filter: Optional[str] = None, query: Optional[str] = None) -> List[dict]:
        """Returns filtered scan history with up-to-date relative date labels."""
        results = []
        for item in self._history:
            # Refresh relative date label dynamically
            item_copy = dict(item)
            item_copy["date_label"] = _format_relative_date(item.get("timestamp", ""))
            item_copy["relative_date"] = item_copy["date_label"]
            item_copy["final_score"] = item_copy.get("score", 0)

            # Filter by risk level
            if risk_filter and risk_filter.upper() != "ALL":
                if item_copy.get("risk_level", "").upper() != risk_filter.upper():
                    continue

            # Filter by query string
            if query and query.strip():
                q = query.strip().lower()
                url_match = q in item_copy.get("url", "").lower()
                host_match = q in item_copy.get("hostname", "").lower()
                display_match = q in item_copy.get("display_url", "").lower()
                if not (url_match or host_match or display_match):
                    continue

            results.append(item_copy)

        return results[:limit]

    def record_scan(self, analysis_data: dict) -> dict:
        """Records a completed scan into history."""
        url = analysis_data.get("url", "").strip()
        hostname = analysis_data.get("hostname", "") or url
        score = analysis_data.get("score", analysis_data.get("final_score", 0))
        risk_level = analysis_data.get("risk_level", "LOW")
        status = analysis_data.get("status", "safe")

        # Create clean display URL (e.g. strip https:// or show path if shortened)
        display_url = url
        if display_url.startswith("https://"):
            display_url = display_url[8:]
        elif display_url.startswith("http://"):
            display_url = display_url[7:]
        if display_url.endswith("/"):
            display_url = display_url[:-1]

        now_iso = datetime.now(timezone.utc).isoformat()
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"

        # Remove duplicate URL entry if already in history to keep latest at top
        self._history = [s for s in self._history if s.get("url", "").lower() != url.lower()]

        snapshot = analysis_data.get("analysis_snapshot") or analysis_data

        item = {
            "id": scan_id,
            "url": url,
            "hostname": hostname,
            "display_url": display_url,
            "score": score,
            "final_score": score,
            "risk_level": risk_level,
            "status": status,
            "timestamp": now_iso,
            "date_label": "Today",
            "relative_date": "Today",
            "analysis_snapshot": snapshot
        }

        self._history.insert(0, item)
        # Cap history to 100 entries
        self._history = self._history[:100]
        self._save_to_disk()
        return item

    def get_scan_by_id(self, scan_id: str) -> Optional[dict]:
        for item in self._history:
            if item.get("id") == scan_id:
                item_copy = dict(item)
                item_copy["date_label"] = _format_relative_date(item.get("timestamp", ""))
                item_copy["relative_date"] = item_copy["date_label"]
                item_copy["final_score"] = item_copy.get("score", 0)
                return item_copy
        return None

    def clear_history(self) -> bool:
        self._history = []
        self._save_to_disk()
        return True

    def reset_seed_history(self) -> List[dict]:
        self._history = _get_seed_history()
        self._save_to_disk()
        return self._history


history_service = ScanHistoryService()


def get_history(limit: int = 50, risk_filter: Optional[str] = None, query: Optional[str] = None) -> List[dict]:
    return history_service.get_history(limit=limit, risk_filter=risk_filter, query=query)


def record_scan(analysis_data: dict) -> dict:
    return history_service.record_scan(analysis_data)


def get_scan_by_id(scan_id: str) -> Optional[dict]:
    return history_service.get_scan_by_id(scan_id)


def clear_history() -> bool:
    return history_service.clear_history()


def reset_seed_history() -> List[dict]:
    return history_service.reset_seed_history()
