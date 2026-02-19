from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# Valid roles (ordered by privilege level)
ROLES = ("student", "staff", "admin")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20), default="student")  # student | staff | admin
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Helpers ────────────────────────────────────────────────────────────────
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_staff(self) -> bool:
        """Staff OR admin — both have elevated privileges."""
        return self.role in ("staff", "admin")

    @property
    def role_label(self) -> str:
        return {"student": "🎓 Student", "staff": "👔 Staff", "admin": "🔐 Admin"}.get(self.role, self.role)

    @property
    def role_color(self) -> str:
        return {
            "student": "hsl(213,94%,60%)",
            "staff":   "hsl(142,71%,45%)",
            "admin":   "hsl(0,85%,60%)",
        }.get(self.role, "var(--text-muted)")

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "username":   self.username,
            "email":      self.email,
            "role":       self.role,
            "is_active":  self.is_active,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M"),
        }
