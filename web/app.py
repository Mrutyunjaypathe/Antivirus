import os
import sys
import uuid
import threading
import platform as _platform

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, Blueprint
from flask_login import LoginManager, login_required, current_user
from werkzeug.utils import secure_filename

from .models import db, User
from .scan_history import add_result, get_all, get_stats, clear_history
from .reports import generate_report, get_all_reports, get_report_file
from .auth import auth_bp
from .admin import admin_bp
import web.quarantine as _quar

import scanner as _scanner_module

# ─── App Factory ─────────────────────────────────────────────────────────────
def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")

    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(DATA_DIR, exist_ok=True)

    app.config["SECRET_KEY"]           = os.environ.get("FLASK_SECRET_KEY", "shieldx-secret-2025-auth")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(DATA_DIR, 'shieldx.db')}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"]   = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 50)) * 1024 * 1024

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

    # ─── Extensions ──────────────────────────────────────────────────────────
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access SHIELDX."
    login_manager.login_message_category = "error"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ─── Register Blueprints ─────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    scanner = _scanner_module.MalwareScanner()

    # initialise quarantine
    _quar.init(DATA_DIR)

    # ── Context processor: inject quarantine count into every template ────────
    @app.context_processor
    def inject_quar_count():
        try:
            from flask_login import current_user
            if current_user.is_authenticated:
                count = sum(
                    1 for e in _quar.get_all(user_id=current_user.id,
                                             admin=getattr(current_user, 'role', '') == 'admin')
                    if e.get('status') == 'quarantined'
                )
                return {'quarantine_count': count}
        except Exception:
            pass
        return {'quarantine_count': 0}

    # ─── Main Blueprint ───────────────────────────────────────────────────────
    main = Blueprint("main", __name__)

    @main.route("/")
    @login_required
    def index():
        uid   = current_user.id
        stats = get_stats(user_id=uid)
        recent= get_all(user_id=uid)[:5]
        return render_template("index.html", stats=stats, recent=recent)

    @main.route("/scan")
    @login_required
    def scan_page():
        return render_template("scan.html")

    @main.route("/scan/file", methods=["POST"])
    @login_required
    def scan_file():
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        filename    = secure_filename(uploaded_file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        save_path   = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

        try:
            uploaded_file.save(save_path)
            result = scanner.scan_file(save_path)
            result["file_name"] = filename

            # Load custom signatures and re-check
            from .admin import _load_custom_sigs
            custom_sigs = [s.encode("utf-8", errors="replace") for s in _load_custom_sigs()]
            if custom_sigs and not result["is_malicious"]:
                try:
                    with open(save_path, "rb") as f:
                        content = f.read()
                    for sig in custom_sigs:
                        if sig in content:
                            result["is_malicious"] = True
                            result["threat_name"]  = "Custom-Signature"
                            result["severity"]     = "HIGH"
                            break
                except Exception:
                    pass

            uid = current_user.id
            add_result(result, user_id=uid)
            report = generate_report(result, user_id=uid)

            # ══ Auto-quarantine if malicious ═════════════════════════════════════
            quar_id = None
            if result["is_malicious"]:
                qentry = _quar.quarantine_file(save_path, result, uid, source="upload")
                if qentry:
                    quar_id   = qentry["id"]
                    save_path = None   # file moved — don’t delete in finally

            return jsonify({
                "file_name":    filename,
                "is_malicious": result["is_malicious"],
                "severity":     result["severity"],
                "threat_name":  result["threat_name"],
                "md5":          result["md5"],
                "sha256":       result["sha256"],
                "metadata":     result["metadata"],
                "scanned_at":   result["scanned_at"],
                "report_id":    report["report_id"],
                "quarantine_id": quar_id,
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            if save_path:   # only delete if NOT already quarantined
                try:
                    os.remove(save_path)
                except Exception:
                    pass

    # ─── Multi-file / Directory Scan ─────────────────────────────────────────
    @main.route("/scan/multi", methods=["POST"])
    @login_required
    def scan_multi():
        files = request.files.getlist("files")
        if not files or all(f.filename == "" for f in files):
            return jsonify({"error": "No files selected"}), 400

        MAX_FILES = 200
        files = [f for f in files if f.filename != ""][:MAX_FILES]

        from .admin import _load_custom_sigs
        custom_sigs = [s.encode("utf-8", errors="replace") for s in _load_custom_sigs()]
        uid     = current_user.id
        results = []

        for uploaded_file in files:
            raw_name = uploaded_file.filename or "unknown"
            # preserve relative path for directory display (e.g. subfolder/file.txt)
            display_name = raw_name.replace("\\", "/")
            filename     = secure_filename(os.path.basename(raw_name))
            if not filename:
                filename = "file"
            unique_name  = f"{uuid.uuid4().hex}_{filename}"
            save_path    = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

            try:
                uploaded_file.save(save_path)
                result = scanner.scan_file(save_path)
                result["file_name"] = display_name

                # Custom-signature check
                if custom_sigs and not result["is_malicious"]:
                    try:
                        with open(save_path, "rb") as f:
                            content = f.read()
                        for sig in custom_sigs:
                            if sig in content:
                                result["is_malicious"] = True
                                result["threat_name"]  = "Custom-Signature"
                                result["severity"]     = "HIGH"
                                break
                    except Exception:
                        pass

                add_result(result, user_id=uid)
                report = generate_report(result, user_id=uid)

                results.append({
                    "file_name":   display_name,
                    "is_malicious":result["is_malicious"],
                    "severity":    result["severity"],
                    "threat_name": result["threat_name"],
                    "md5":         result["md5"],
                    "scanned_at":  result["scanned_at"],
                    "report_id":   report["report_id"],
                    "size":        result.get("metadata", {}).get("size", "—"),
                    "error":       None,
                })
            except Exception as e:
                results.append({
                    "file_name":   display_name,
                    "is_malicious":None,
                    "severity":    None,
                    "threat_name": None,
                    "error":       str(e),
                })
            finally:
                try:
                    os.remove(save_path)
                except Exception:
                    pass

        total   = len(results)
        threats = sum(1 for r in results if r.get("is_malicious"))
        clean   = sum(1 for r in results if r.get("is_malicious") is False)
        errors  = sum(1 for r in results if r.get("error"))

        return jsonify({
            "results": results,
            "summary": {
                "total":   total,
                "threats": threats,
                "clean":   clean,
                "errors":  errors,
            }
        })


    @main.route("/history")
    @login_required
    def history_page():
        uid        = current_user.id
        staff_view = current_user.is_staff   # staff + admin see ALL users
        if staff_view:
            history = get_all(user_id=None)  # all users
            stats   = get_stats(user_id=None)
            # Attach username to each entry for display
            user_map = {u.id: u.username for u in User.query.all()}
            for e in history:
                e["username"] = user_map.get(e.get("user_id"), "Unknown")
        else:
            history = get_all(user_id=uid)
            stats   = get_stats(user_id=uid)
        return render_template("history.html", history=history, stats=stats,
                               staff_view=staff_view)

    @main.route("/history/clear", methods=["POST"])
    @login_required
    def clear_history_route():
        clear_history(user_id=current_user.id)
        flash("Your scan history has been cleared.", "success")
        return redirect(url_for("main.history_page"))

    @main.route("/reports")
    @login_required
    def reports_page():
        staff_view = current_user.is_staff
        if staff_view:
            reports = get_all_reports(user_id=None)   # all reports
            user_map = {u.id: u.username for u in User.query.all()}
        else:
            reports  = get_all_reports(user_id=current_user.id)
            user_map = {}
        return render_template("reports.html", reports=reports,
                               staff_view=staff_view, user_map=user_map)

    @main.route("/reports/download/<filename>")
    @login_required
    def download_report(filename):
        path = get_report_file(filename)
        if not path:
            flash("Report not found.", "error")
            return redirect(url_for("main.reports_page"))
        return send_file(path, as_attachment=True, download_name=filename)

    @main.route("/reports/download/pdf/<filename>")
    @login_required
    def download_report_pdf(filename):
        # 1. Get raw JSON path
        path = get_report_file(filename)
        if not path:
            flash("Report not found.", "error")
            return redirect(url_for("main.reports_page"))

        # 2. Generate PDF
        try:
            with open(path) as f:
                report_data = json.load(f)

            from .pdf_generator import create_pdf_bytes
            pdf_buffer = create_pdf_bytes(report_data)

            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=filename.replace(".json", ".pdf"),
                mimetype="application/pdf"
            )
        except Exception as e:
            flash(f"Error generating PDF: {str(e)}", "error")
            return redirect(url_for("main.reports_page"))

    @main.route("/about")
    @login_required
    def about_page():
        return render_template("about.html")

    @main.route("/api/stats")
    @login_required
    def api_stats():
        return jsonify(get_stats(user_id=current_user.id))

    @main.route("/api/chart-data")
    @login_required
    def api_chart_data():
        from datetime import datetime, timedelta
        history = get_all(user_id=current_user.id)

        # ── 1. Daily trend — last 7 days ──────────────────────────────────
        today = datetime.now().date()
        days  = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
        day_labels     = [d.strftime("%b %d") for d in days]
        scans_per_day  = [0] * 7
        threats_per_day = [0] * 7
        for entry in history:
            try:
                edate = datetime.strptime(entry["scanned_at"], "%Y-%m-%d %H:%M:%S").date()
                if edate in days:
                    idx = days.index(edate)
                    scans_per_day[idx] += 1
                    if entry.get("is_malicious"):
                        threats_per_day[idx] += 1
            except Exception:
                pass

        # ── 2. Verdict split ───────────────────────────────────────────────
        total   = len(history)
        threats = sum(1 for e in history if e.get("is_malicious"))
        clean   = total - threats

        # ── 3. Severity breakdown ──────────────────────────────────────────
        sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for entry in history:
            sev = (entry.get("severity") or "").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1

        # ── 4. Top threat names ────────────────────────────────────────────
        threat_names = {}
        for entry in history:
            if entry.get("is_malicious") and entry.get("threat_name"):
                n = entry["threat_name"]
                threat_names[n] = threat_names.get(n, 0) + 1
        top_threats = sorted(threat_names.items(), key=lambda x: x[1], reverse=True)[:6]

        # ── 5. File-type distribution ──────────────────────────────────────
        ext_counts = {}
        for entry in history:
            fname = entry.get("file_name", "")
            ext = os.path.splitext(fname)[1].lower() if "." in fname else "other"
            ext = ext or "other"
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
        top_exts = sorted(ext_counts.items(), key=lambda x: x[1], reverse=True)[:7]

        return jsonify({
            "daily": {
                "labels":  day_labels,
                "scans":   scans_per_day,
                "threats": threats_per_day,
            },
            "verdict": {"clean": clean, "threats": threats},
            "severity": sev_counts,
            "top_threats": {
                "labels": [t[0] for t in top_threats],
                "data":   [t[1] for t in top_threats],
            },
            "file_types": {
                "labels": [e[0] for e in top_exts],
                "data":   [e[1] for e in top_exts],
            },
        })

    # ═══════════════════════════════════════════════════════════════════════════
    #  QUARANTINE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════════

    @main.route("/quarantine")
    @login_required
    def quarantine_page():
        uid      = current_user.id
        is_admin = current_user.role == "admin"
        entries  = _quar.get_all(user_id=uid, admin=is_admin)
        stats    = _quar.get_stats()
        return render_template("quarantine.html", entries=entries, stats=stats)

    @main.route("/quarantine/restore/<qid>", methods=["POST"])
    @login_required
    def quarantine_restore(qid):
        data         = request.get_json() or {}
        restore_path = (data.get("path") or "").strip()
        entry        = _quar.get_entry(qid)
        if not entry:
            return jsonify({"error": "Not found"}), 404
        if not restore_path:
            restore_path = entry.get("original_path") or ""
        if not restore_path:
            return jsonify({"error": "No restore path specified"}), 400
        is_admin = current_user.role == "admin"
        ok, msg  = _quar.restore_file(qid, restore_path, current_user.id, admin=is_admin)
        return jsonify({"ok": ok, "message": msg})

    @main.route("/quarantine/delete/<qid>", methods=["POST"])
    @login_required
    def quarantine_delete(qid):
        is_admin = current_user.role == "admin"
        ok       = _quar.delete_permanently(qid, current_user.id, admin=is_admin)
        return jsonify({"ok": ok})

    @main.route("/quarantine/from-path", methods=["POST"])
    @login_required
    def quarantine_from_path():
        """Quarantine a server-side file (from drive scan results)."""
        data     = request.get_json() or {}
        src_path = (data.get("path") or "").strip()
        if not src_path or not os.path.exists(src_path):
            return jsonify({"error": "File not found on server"}), 404
        scan_result = {
            "file_name":   data.get("file_name") or os.path.basename(src_path),
            "threat_name": data.get("threat_name"),
            "severity":    data.get("severity"),
            "md5":         data.get("md5", ""),
            "sha256":      "",
        }
        entry = _quar.quarantine_file(src_path, scan_result, current_user.id,
                                      source="drive_scan")
        if not entry:
            return jsonify({"error": "Quarantine failed — check server permissions"}), 500
        return jsonify({"ok": True, "id": entry["id"]})

    # ═══════════════════════════════════════════════════════════════════════════
    #  USB / EXTERNAL DRIVE SCANNING
    # ═══════════════════════════════════════════════════════════════════════════

    # In-memory job store (job_id -> dict)
    _drive_jobs = {}

    def _list_drives():
        """Return list of drive dicts — cross-platform."""
        drives = []
        if _platform.system() == "Windows":
            import ctypes, string as _str
            TYPE_NAME = {2: "USB / Removable", 3: "Local Disk", 4: "Network Drive", 5: "CD / DVD", 6: "RAM Disk"}
            TYPE_ICON = {2: "🔌", 3: "💾", 4: "🌐", 5: "📀", 6: "⚡"}
            for letter in _str.ascii_uppercase:
                path = f"{letter}:\\"
                if not os.path.exists(path):
                    continue
                try:
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(path)
                    if drive_type == 1:        # No root dir — invalid
                        continue
                    # Volume label
                    vol = ctypes.create_unicode_buffer(261)
                    ctypes.windll.kernel32.GetVolumeInformationW(path, vol, 261, None, None, None, None, 0)
                    # Total size
                    total = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(path, None, ctypes.byref(total), None)
                    size_gb = round(total.value / (1024 ** 3), 1) if total.value else 0
                    drives.append({
                        "letter":       letter + ":",
                        "path":         path,
                        "label":        vol.value or f"Drive ({letter}:)",
                        "type":         TYPE_NAME.get(drive_type, "Unknown"),
                        "type_id":      drive_type,
                        "is_removable": drive_type == 2,
                        "size_gb":      size_gb,
                        "icon":         TYPE_ICON.get(drive_type, "💾"),
                    })
                except Exception:
                    drives.append({
                        "letter": letter + ":", "path": path,
                        "label": f"Drive ({letter}:)", "type": "Unknown",
                        "type_id": 0, "is_removable": False,
                        "size_gb": 0, "icon": "💾",
                    })
        else:
            # Linux / macOS — check common mount points
            for mp in ["/media", "/mnt", "/Volumes", "/run/media"]:
                if not os.path.isdir(mp):
                    continue
                try:
                    for name in os.listdir(mp):
                        path = os.path.join(mp, name)
                        if os.path.ismount(path):
                            drives.append({
                                "letter": name, "path": path,
                                "label": name, "type": "Removable",
                                "type_id": 2, "is_removable": True,
                                "size_gb": 0, "icon": "🔌",
                            })
                except Exception:
                    pass
        return drives

    def _do_drive_scan(job_id, drive_path, user_id, quick_mode):
        """Background thread: walk drive, scan each file, update _drive_jobs[job_id]."""
        job = _drive_jobs[job_id]

        SKIP_DIRS = {
            "System Volume Information", "$RECYCLE.BIN", "$Recycle.Bin",
            "Recovery", "Config.Msi", "WindowsApps", "$WinREAgent",
        }
        MAX_FILES    = 5000           # Hard cap
        MAX_FILE_MB  = 100            # Skip files > 100 MB

        # Load custom signatures
        try:
            from .admin import _load_custom_sigs
            custom_sigs = [s.encode("utf-8", errors="replace") for s in _load_custom_sigs()]
        except Exception:
            custom_sigs = []

        # ── Phase 1: collect file list ────────────────────────────────────
        job["status"] = "indexing"
        all_files = []
        try:
            for root, dirs, files in os.walk(drive_path, onerror=lambda e: None):
                # Skip system directories
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                # Quick mode: only top 2 levels
                if quick_mode:
                    depth = root.replace(drive_path.rstrip("/\\"), "").count(os.sep)
                    if depth >= 2:
                        dirs[:] = []
                for fname in files:
                    if job.get("cancelled"):
                        break
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.getsize(fpath) <= MAX_FILE_MB * 1024 * 1024:
                            all_files.append(fpath)
                    except OSError:
                        pass
                    if len(all_files) >= MAX_FILES:
                        break
                if len(all_files) >= MAX_FILES or job.get("cancelled"):
                    break
        except Exception as e:
            job["status"] = "error"
            job["error"]  = str(e)
            return

        job["total"]  = len(all_files)
        job["status"] = "scanning"

        # ── Phase 2: scan each file ───────────────────────────────────────
        results = []
        for i, fpath in enumerate(all_files):
            if job.get("cancelled"):
                job["status"] = "cancelled"
                break

            job["progress"]     = i + 1
            job["current_file"] = os.path.basename(fpath)

            try:
                result = scanner.scan_file(fpath)

                # Custom signature check (read first 512 KB only)
                if custom_sigs and not result["is_malicious"]:
                    try:
                        with open(fpath, "rb") as f:
                            chunk = f.read(512 * 1024)
                        for sig in custom_sigs:
                            if sig in chunk:
                                result["is_malicious"] = True
                                result["threat_name"]  = "Custom-Signature"
                                result["severity"]     = "HIGH"
                                break
                    except Exception:
                        pass

                # Only save THREATS to history (avoid flooding clean scan history)
                if result["is_malicious"]:
                    add_result(result, user_id=user_id)
                    generate_report(result, user_id=user_id)

                results.append({
                    "file_name":   fpath,
                    "is_malicious":result["is_malicious"],
                    "severity":    result["severity"],
                    "threat_name": result["threat_name"],
                    "md5":         result["md5"],
                    "size":        result.get("metadata", {}).get("size", "—"),
                    "error":       None,
                })
            except Exception as e:
                results.append({
                    "file_name":   fpath,
                    "error":       str(e)[:100],
                    "is_malicious":None,
                    "severity":    None,
                    "threat_name": None,
                })

        total   = len(results)
        threats = sum(1 for r in results if r.get("is_malicious"))
        clean   = sum(1 for r in results if r.get("is_malicious") is False)
        errors  = sum(1 for r in results if r.get("error"))

        if job["status"] != "cancelled":
            job["status"] = "done"
        job["results"] = results
        job["summary"] = {
            "total": total, "threats": threats,
            "clean": clean, "errors": errors,
        }

    @main.route("/api/drives")
    @login_required
    def api_drives():
        return jsonify(_list_drives())

    @main.route("/scan/drive/start", methods=["POST"])
    @login_required
    def scan_drive_start():
        data       = request.get_json() or {}
        drive_path = (data.get("path") or "").strip()
        quick      = bool(data.get("quick", False))
        if not drive_path or not os.path.exists(drive_path):
            return jsonify({"error": "Invalid drive path"}), 400
        # Validate: path must be a known drive root
        known_paths = [d["path"] for d in _list_drives()]
        if not any(drive_path.rstrip("/\\").lower() == k.rstrip("/\\").lower() for k in known_paths):
            return jsonify({"error": "Path not allowed"}), 403

        job_id = uuid.uuid4().hex
        _drive_jobs[job_id] = {
            "status": "starting", "progress": 0, "total": 0,
            "current_file": "", "results": None, "summary": None,
            "error": None, "cancelled": False,
        }
        t = threading.Thread(
            target=_do_drive_scan,
            args=(job_id, drive_path, current_user.id, quick),
            daemon=True,
        )
        t.start()
        return jsonify({"job_id": job_id})

    @main.route("/scan/network/start", methods=["POST"])
    @login_required
    def scan_network_start():
        """Start a network share scan (UNC path)."""
        data     = request.get_json() or {}
        net_path = (data.get("path") or "").strip()
        quick    = bool(data.get("quick", False))

        if not net_path:
             return jsonify({"error": "Path required"}), 400

        # Enforce UNC format (basic check)
        is_unc = net_path.startswith(r"\\") or net_path.startswith("//")
        if not is_unc:
            return jsonify({"error": "Only network paths (UNC) are allowed here. e.g. \\\\server\\share"}), 400

        if not os.path.exists(net_path):
             return jsonify({"error": "Network path not accessible or does not exist."}), 404

        # Reuse drive scan machinery
        job_id = uuid.uuid4().hex
        _drive_jobs[job_id] = {
            "status": "starting", "progress": 0, "total": 0,
            "current_file": "", "results": None, "summary": None,
            "error": None, "cancelled": False,
        }
        t = threading.Thread(
            target=_do_drive_scan,
            args=(job_id, net_path, current_user.id, quick),
            daemon=True,
        )
        t.start()
        return jsonify({"job_id": job_id})

    @main.route("/api/drive/status/<job_id>")
    @login_required
    def drive_status(job_id):
        job = _drive_jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        resp = {
            "status":       job["status"],
            "progress":     job["progress"],
            "total":        job["total"],
            "current_file": job["current_file"],
            "summary":      job["summary"],
            "error":        job["error"],
        }
        if job["status"] in ("done", "cancelled"):
            resp["results"] = job["results"]
        return jsonify(resp)

    @main.route("/scan/drive/cancel/<job_id>", methods=["POST"])
    @login_required
    def drive_cancel(job_id):
        job = _drive_jobs.get(job_id)
        if job:
            job["cancelled"] = True
        return jsonify({"ok": True})

    # ─── Error handlers ──────────────────────────────────────────────────────
    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "File too large. Maximum 50MB."}), 413

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    app.register_blueprint(main)

    # ─── DB Init + Default Admin ──────────────────────────────────────────────
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", email="admin@shieldx.local", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            print("  ✅ Default admin created: admin / admin123")

    return app


# Expose app at module level for run.py
app = create_app()
