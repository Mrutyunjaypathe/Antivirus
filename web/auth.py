from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User

auth_bp = Blueprint("auth", __name__)


# ── Role-based decorators ──────────────────────────────────────────────────────

def staff_required(f):
    """Allow staff AND admin. Blocks students."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_staff:
            flash("Staff or Admin access required for this page.", "error")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Allow admin only."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated


# ── Login ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash("Invalid username or password.", "error")
            return render_template("auth/login.html")

        if not user.is_active:
            flash("Your account has been deactivated. Contact admin.", "error")
            return render_template("auth/login.html")

        login_user(user, remember=remember)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("main.index"))

    return render_template("auth/login.html")


# ── Register ──────────────────────────────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "student")

        # Role gate — admin cannot self-register
        if role not in ("student", "staff"):
            role = "student"

        # Validations
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("auth/register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return render_template("auth/register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("auth/register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return render_template("auth/register.html")

        # First user ever → auto-promote to admin
        is_first_user = User.query.count() == 0

        user = User(username=username, email=email,
                    role="admin" if is_first_user else role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if is_first_user:
            flash("Admin account created! You are the first user — administrator access granted.", "success")
        else:
            flash(f"Account created as {user.role_label}! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


# ── Logout ────────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
