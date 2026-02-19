"""
SHIELDX — Quarantine Manager
Moves malicious files to a locked quarantine directory,
renamed with a .quar extension so they cannot be executed.
"""
import os
import json
import uuid
import shutil
from datetime import datetime

_QUARANTINE_DIR = None
_INDEX_FILE     = None


def init(data_dir: str):
    global _QUARANTINE_DIR, _INDEX_FILE
    _QUARANTINE_DIR = os.path.join(data_dir, "quarantine")
    _INDEX_FILE     = os.path.join(data_dir, "quarantine_index.json")
    os.makedirs(_QUARANTINE_DIR, exist_ok=True)


# ── Index helpers ─────────────────────────────────────────────────────────────

def _load() -> list:
    if not _INDEX_FILE or not os.path.exists(_INDEX_FILE):
        return []
    try:
        with open(_INDEX_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save(entries: list):
    with open(_INDEX_FILE, "w") as f:
        json.dump(entries, f, indent=2)


# ── Public API ────────────────────────────────────────────────────────────────

def quarantine_file(src_path: str, scan_result: dict, user_id: int,
                    source: str = "upload") -> dict | None:
    """
    Move *src_path* into quarantine.
    Returns the quarantine entry dict, or None on failure.
    """
    if not src_path or not os.path.exists(src_path):
        return None

    qid           = uuid.uuid4().hex
    quar_filename = f"{qid}.quar"
    quar_path     = os.path.join(_QUARANTINE_DIR, quar_filename)

    try:
        shutil.move(src_path, quar_path)
    except Exception:
        return None

    entry = {
        "id":              qid,
        "original_name":   scan_result.get("file_name") or os.path.basename(src_path),
        "original_path":   src_path,
        "quarantine_file": quar_filename,
        "threat_name":     scan_result.get("threat_name"),
        "severity":        scan_result.get("severity"),
        "md5":             scan_result.get("md5"),
        "sha256":          scan_result.get("sha256"),
        "quarantined_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id":         user_id,
        "source":          source,          # "upload" | "drive_scan" | "multi"
        "status":          "quarantined",   # quarantined | restored | deleted
        "restore_path":    None,
    }

    index = _load()
    index.insert(0, entry)
    _save(index)
    return entry


def get_all(user_id: int = None, admin: bool = False) -> list:
    index = _load()
    if admin:
        return index
    if user_id is not None:
        return [e for e in index if e.get("user_id") == user_id]
    return []


def get_entry(qid: str) -> dict | None:
    for e in _load():
        if e["id"] == qid:
            return e
    return None


def restore_file(qid: str, restore_path: str, user_id: int,
                 admin: bool = False) -> tuple[bool, str]:
    """Move quarantined file back to *restore_path*."""
    index = _load()
    for entry in index:
        if entry["id"] != qid:
            continue
        if not admin and entry.get("user_id") != user_id:
            return False, "Permission denied"
        if entry["status"] != "quarantined":
            return False, f"File is already {entry['status']}"
        quar_path = os.path.join(_QUARANTINE_DIR, entry["quarantine_file"])
        if not os.path.exists(quar_path):
            return False, "Quarantine file missing — may have been deleted manually"
        try:
            parent = os.path.dirname(restore_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.move(quar_path, restore_path)
            entry["status"]       = "restored"
            entry["restore_path"] = restore_path
            _save(index)
            return True, "File restored successfully"
        except Exception as exc:
            return False, str(exc)
    return False, "Entry not found"


def delete_permanently(qid: str, user_id: int, admin: bool = False) -> bool:
    """Permanently delete the quarantined file and mark entry as deleted."""
    index = _load()
    for entry in index:
        if entry["id"] != qid:
            continue
        if not admin and entry.get("user_id") != user_id:
            return False
        quar_path = os.path.join(_QUARANTINE_DIR, entry["quarantine_file"])
        try:
            if os.path.exists(quar_path):
                os.remove(quar_path)
        except Exception:
            pass
        entry["status"] = "deleted"
        _save(index)
        return True
    return False


def get_stats() -> dict:
    index = _load()
    return {
        "total":       len(index),
        "quarantined": sum(1 for e in index if e.get("status") == "quarantined"),
        "restored":    sum(1 for e in index if e.get("status") == "restored"),
        "deleted":     sum(1 for e in index if e.get("status") == "deleted"),
    }
