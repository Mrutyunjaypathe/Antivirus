import json
import os
import uuid
from datetime import datetime

REPORTS_DIR   = os.path.join(os.path.dirname(__file__), "data", "reports")
REPORTS_INDEX = os.path.join(os.path.dirname(__file__), "data", "reports_index.json")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _load_index():
    if not os.path.exists(REPORTS_INDEX):
        return []
    try:
        with open(REPORTS_INDEX) as f:
            return json.load(f)
    except Exception:
        return []


def _save_index(data):
    with open(REPORTS_INDEX, "w") as f:
        json.dump(data, f, indent=2)


def generate_report(scan_result: dict, user_id: int = None) -> dict:
    report_id = str(uuid.uuid4())[:8].upper()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename  = f"report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath  = os.path.join(REPORTS_DIR, filename)

    report_data = {
        "report_id":    report_id,
        "generated_at": timestamp,
        "user_id":      user_id,
        "summary": {
            "file_name":  scan_result.get("file_name"),
            "verdict":    "THREAT DETECTED" if scan_result.get("is_malicious") else "CLEAN",
            "severity":   scan_result.get("severity", "N/A"),
            "threat_name":scan_result.get("threat_name", "N/A"),
        },
        "file_details": {
            "md5":    scan_result.get("md5"),
            "sha256": scan_result.get("sha256"),
            **scan_result.get("metadata", {}),
        },
        "scan_details": {
            "scanned_at":        scan_result.get("scanned_at"),
            "engine_version":    "SHIELDX v2.0",
            "signatures_loaded": 57,
        },
        "recommendations": _get_recommendations(scan_result),
    }

    with open(filepath, "w") as f:
        json.dump(report_data, f, indent=2)

    index = _load_index()
    index.insert(0, {
        "report_id":    report_id,
        "user_id":      user_id,
        "file_name":    scan_result.get("file_name"),
        "verdict":      report_data["summary"]["verdict"],
        "severity":     scan_result.get("severity", "N/A"),
        "generated_at": timestamp,
        "filename":     filename,
    })
    _save_index(index)
    return report_data


def get_all_reports(user_id=None):
    index = _load_index()
    if user_id is None:
        return index
    return [r for r in index if r.get("user_id") == user_id]


def get_report_file(filename):
    path = os.path.join(REPORTS_DIR, filename)
    return path if os.path.exists(path) else None


def _get_recommendations(scan_result):
    if not scan_result.get("is_malicious"):
        return ["File appears clean. No action needed."]
    severity = scan_result.get("severity", "")
    recs = ["Immediately quarantine or delete the file."]
    if severity == "CRITICAL":
        recs += [
            "Run a full system scan immediately.",
            "Disconnect from network if ransomware is suspected.",
            "Report the incident to your IT security team.",
        ]
    elif severity == "HIGH":
        recs += [
            "Do not execute or open the file.",
            "Check for related suspicious files in the same directory.",
        ]
    else:
        recs.append("Monitor system for unusual behavior.")
    return recs
