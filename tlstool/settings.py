import os

from dotenv import load_dotenv
load_dotenv()

def _bool(name, default=False):
    """Parse a boolean environment variable with sensible defaults.

    Reads the environment variable `name` and interprets truthy values in a
    case-insensitive manner. Recognized truthy strings are: "1", "true",
    "yes", and "on". If the variable is unset, returns `default`.

    Args:
        name (str): Environment variable name to read.
        default (bool, optional): Value to return when the variable is unset.
            Defaults to False.

    Returns:
        bool: Parsed boolean value from the environment or the provided default.
    """
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in {"1","true","yes","on"}

# Flask
FLASK_ENV = os.getenv("FLASK_ENV", "local")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "")
APPLICATION_ROOT = os.getenv("APPLICATION_ROOT", "/")
SESSION_COOKIE_PATH = os.getenv("SESSION_COOKIE_PATH", "/")
FLASK_APP = os.getenv("FLASK_APP", "tlstool")
FLASK_DEBUG = _bool("FLASK_DEBUG", False)

# Database
# ==========================================================================
DBNAME = os.getenv("DBNAME", "")
DBHOST = os.getenv("DBHOST", "")
DBUSER = os.getenv("DBUSER", "")
DBPWD = os.getenv("DBPWD", "")
SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI") or (
    f"postgresql://{DBUSER}:{DBPWD}@{DBHOST}:5432/{DBNAME}" if all([DBUSER, DBPWD, DBHOST, DBNAME]) else ""
)
SQLALCHEMY_TRACK_MODIFICATIONS = _bool("SQLALCHEMY_TRACK_MODIFICATIONS", False)

# AWS
# ==========================================================================
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY", "")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY", "")
AWS_REGION_NAME = os.getenv("AWS_REGION_NAME", "us-east-1")

# Fastly
# ==========================================================================
FASTLY_API_TOKEN = os.getenv("FASTLY_API_TOKEN", "")
FASTLY_TLS_CONFIGURATION_ID = os.getenv("FASTLY_TLS_CONFIGURATION_ID", "")

# Lets Encrypt
# ==========================================================================
LE_DIRECTORY_URL = os.getenv("LE_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")
LE_ACCOUNT_KEY_SECRET_NAME = os.getenv("LE_ACCOUNT_KEY_SECRET_NAME", "")
LE_ACCOUNT_KEY_SECRET = os.getenv("LE_ACCOUNT_KEY_SECRET", {})

# Slack
# ==========================================================================
ENABLE_SLACK_NOTIFICATIONS = _bool("ENABLE_SLACK_NOTIFICATIONS", False)
SLACK_WEBHOOK_KEY = os.getenv("SLACK_WEBHOOK_KEY", "")
SLACK_WORKSPACE_ID = os.getenv("SLACK_WORKSPACE_ID", "")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")

# Other application values
# ==========================================================================
LOG_FORMAT = os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s L%(lineno)d - %(levelname)s - %(message)s")
PEM_SECRET_BASE_PATH = os.getenv("PEM_SECRET_BASE_PATH", "pem-secret-")
RENEWAL_WINDOW_DAYS = int(os.getenv("RENEWAL_WINDOW_DAYS", "15"))
