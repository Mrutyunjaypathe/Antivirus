import json
import os
from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user

from .models import db, User, ROLES
from .scan_history import get_all, get_stats
from .reports import get_all_reports

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

CUSTOM_SIGS_FILE = os.path.join(os.path.dirname(__file__), "data", "custom_signatures.json")
os.makedirs(os.path.dirname(CUSTOM_SIGS_FILE), exist_ok=True)


# ─── Admin-required decorator ─────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated


# ─── Admin Dashboard ──────────────────────────────────────────────────────────
@admin_bp.route("/")
@admin_required
def dashboard():
    stats        = get_stats(user_id=None)
    recent       = get_all(user_id=None)[:10]
    all_users    = User.query.order_by(User.created_at.desc()).all()
    total_users  = len(all_users)
    active_users = sum(1 for u in all_users if u.is_active)
    total_reports= len(get_all_reports(user_id=None))

    # Role breakdown for dashboard
    role_counts  = {r: sum(1 for u in all_users if u.role == r) for r in ROLES}

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent=recent,
        total_users=total_users,
        active_users=active_users,
        total_reports=total_reports,
        role_counts=role_counts,
    )


# ─── User Management ──────────────────────────────────────────────────────────
@admin_bp.route("/users")
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=all_users, roles=ROLES)


@admin_bp.route("/users/<int:user_id>/set-role", methods=["POST"])
@admin_required
def set_role(user_id):
    """Set a user's role to an arbitrary value from the ROLES list."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot change your own role.", "error")
        return redirect(url_for("admin.users"))
    new_role = request.form.get("role", "student")
    if new_role not in ROLES:
        flash("Invalid role.", "error")
        return redirect(url_for("admin.users"))
    user.role = new_role
    db.session.commit()
    flash(f"✅ {user.username} is now {user.role_label}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle-role", methods=["POST"])
@admin_required
def toggle_role(user_id):
    """Cycle through roles: student → staff → admin → student …"""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot change your own role.", "error")
    else:
        idx       = list(ROLES).index(user.role) if user.role in ROLES else 0
        user.role = ROLES[(idx + 1) % len(ROLES)]
        db.session.commit()
        flash(f"✅ {user.username} is now {user.role_label}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate yourself.", "error")
    else:
        user.is_active = not user.is_active
        db.session.commit()
        status = "activated" if user.is_active else "deactivated"
        flash(f"User '{user.username}' has been {status}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete yourself.", "error")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' deleted.", "success")
    return redirect(url_for("admin.users"))


# ─── All History (admin) ──────────────────────────────────────────────────────
@admin_bp.route("/history")
@admin_required
def history():
    all_history = get_all(user_id=None)
    stats       = get_stats(user_id=None)
    return render_template("admin/history.html", history=all_history, stats=stats)


# ─── Signature Management ─────────────────────────────────────────────────────
def _load_custom_sigs():
    if not os.path.exists(CUSTOM_SIGS_FILE):
        return []
    try:
        with open(CUSTOM_SIGS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_custom_sigs(sigs):
    with open(CUSTOM_SIGS_FILE, "w") as f:
        json.dump(sigs, f, indent=2)


@admin_bp.route("/signatures")
@admin_required
def signatures():
    from scanner import MalwareScanner
    s = MalwareScanner()
    built_in = [sig.decode("utf-8", errors="replace") for sig in s.malware_signatures]
    custom   = _load_custom_sigs()
    return render_template("admin/signatures.html", built_in=built_in, custom=custom)


@admin_bp.route("/signatures/add", methods=["POST"])
@admin_required
def add_signature():
    sig = request.form.get("signature", "").strip()
    if not sig:
        flash("Signature cannot be empty.", "error")
        return redirect(url_for("admin.signatures"))
    custom = _load_custom_sigs()
    if sig in custom:
        flash("Signature already exists.", "error")
    else:
        custom.append(sig)
        _save_custom_sigs(custom)
        flash("Custom signature added.", "success")
    return redirect(url_for("admin.signatures"))


@admin_bp.route("/signatures/delete/<int:idx>", methods=["POST"])
@admin_required
def delete_signature(idx):
    custom = _load_custom_sigs()
    if 0 <= idx < len(custom):
        removed = custom.pop(idx)
        _save_custom_sigs(custom)
        flash(f"Signature removed: {removed[:40]}...", "success")
    return redirect(url_for("admin.signatures"))
