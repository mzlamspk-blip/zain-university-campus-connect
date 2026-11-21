import os
import secrets
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _load_secret() -> str:
    value = os.getenv("FLASK_SECRET_KEY", "").strip()
    weak_markers = ("replace", "change", "dev-only", "secret")
    if len(value) >= 32 and not any(marker in value.lower() for marker in weak_markers):
        return value
    # Never start with a known/default signing key.
    return secrets.token_hex(32)


class Config:
    SECRET_KEY = _load_secret()

    # MongoDB (Atlas or local)
    MONGODB_URI = os.getenv("MONGODB_URI", "")
    MONGODB_DB = os.getenv("MONGODB_DB", "zain_university")

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "CHANGE_ME")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "CHANGE_ME")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE_ME")

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    # Uploads live outside static/ so they can only be reached through the
    # authenticated /media routes.
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
