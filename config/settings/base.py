"""Settings shared by every environment.

Machine-specific values (secrets, hosts, scanner address) are read from the
environment, loaded from a git-ignored ``.env`` at the project root. See
``.env.example`` for the full list of variables.

Nothing in this module should be edited to point at a particular machine; that
belongs in ``dev.py``, ``prod.py``, or ``.env``.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# ``base.py`` is at <project>/config/settings/base.py, so the project root is
# three levels up.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load .env before any setting reads the environment. Real environment
# variables win: load_dotenv does not overwrite by default.
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable, accepting 1/true/yes/on."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    """Read a comma-separated environment variable into a list of strings."""
    raw = os.getenv(name, default)
    return [part.strip() for part in raw.split(",") if part.strip()]


# --- Core ---------------------------------------------------------------

# No default: each environment module must supply one, so a missing key fails
# loudly at startup instead of silently signing sessions with an empty string.
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")

DEBUG = False

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Background task queue for ZAP scans (Phase 5).
    "django_q",
    "accounts",
    "projects",
    "phases",
    "vulns",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"


# --- Database -----------------------------------------------------------

# SQLite is the development default and needs no setup. Setting DB_ENGINE to
# `postgresql` (for demo/deployment) switches to PostgreSQL, which needs the
# `psycopg` package installed in the environment that uses it.
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").strip().lower()

if DB_ENGINE == "postgresql":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME", "secure_sdlc"),
            "USER": os.getenv("DB_USER", ""),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", "localhost"),
            "PORT": os.getenv("DB_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# --- Authentication -----------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Set in Phase 1 once the accounts app defines the custom User model.
AUTH_USER_MODEL = "accounts.User"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"


# --- Internationalisation -----------------------------------------------

LANGUAGE_CODE = "en-gb"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# --- Static and media ---------------------------------------------------

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# --- Django-Q2 (background scans) ---------------------------------------

# timeout must exceed SCAN_TIMEOUT_SECONDS below, or the worker kills a scan
# that the task itself would have ended cleanly. retry must exceed timeout.
Q_CLUSTER = {
    "name": "secure_sdlc",
    "orm": "default",
    "workers": 2,
    "timeout": 1200,
    "retry": 1500,
    "catch_up": False,
    "label": "Django Q",
}


# --- Security tooling ---------------------------------------------------

# OWASP ZAP daemon address. The key is blank in development because ZAP runs
# with its API key disabled there; production reads it from the environment.
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

# Scan safety (CLAUDE.md section 5.5). A scan target whose host is not in this
# list is rejected by ScanTarget.clean() and refused again by the task itself.
SCAN_ALLOWED_HOSTS = env_list(
    "SCAN_ALLOWED_HOSTS",
    "localhost,127.0.0.1,host.docker.internal,juice-shop",
)

# Hard cap on a single scan, in seconds. On expiry the scan is marked FAILED.
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "900"))
