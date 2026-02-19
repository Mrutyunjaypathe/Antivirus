import json
import os
import uuid
from datetime import datetime

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "scan_history.json")
os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)


def _load():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save(data):
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def add_result(scan_result: dict, user_id: int = None) -> str:
    history = _load()
    entry = {
        "id":         str(uuid.uuid4()),
        "user_id":    user_id,
        "file_name":  scan_result.get("file_name"),
        "is_malicious": scan_result.get("is_malicious"),
        "severity":   scan_result.get("severity"),
        "threat_name":scan_result.get("threat_name"),
        "md5":        scan_result.get("md5"),
        "sha256":     scan_result.get("sha256"),
        "metadata":   scan_result.get("metadata", {}),
        "scanned_at": scan_result.get("scanned_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    }
    history.insert(0, entry)
    _save(history[:1000])
    return entry["id"]


def get_all(user_id=None):
    """Return all entries. If user_id is given, filter to that user only."""
    history = _load()
    if user_id is None:
        return history
    return [e for e in history if e.get("user_id") == user_id]


def get_stats(user_id=None):
    history = get_all(user_id=user_id)
    total    = len(history)
    threats  = sum(1 for e in history if e.get("is_malicious"))
    critical = sum(1 for e in history if e.get("severity") == "CRITICAL")
    high     = sum(1 for e in history if e.get("severity") == "HIGH")
    return {
        "total_scans":   total,
        "threats_found": threats,
        "clean_files":   total - threats,
        "critical":      critical,
        "high":          high,
    }


def clear_history(user_id=None):
    if user_id is None:
        _save([])
    else:
        history = [e for e in _load() if e.get("user_id") != user_id]
        _save(history)
