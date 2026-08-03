"""Configuration template for API credentials and runtime constants.

Fill these before running.
"""

SHODAN_API_KEY = ""
VIRUSTOTAL_API_KEY = ""
NVD_API_KEY = ""
# Fill these before running.

REQUEST_TIMEOUT_SECONDS = 5
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.5

DEFAULT_RUNTIME_PROFILE = "standard"
RUNTIME_PROFILES = {
    "quick": {"timeout_seconds": 3, "retry_attempts": 2, "retry_backoff_seconds": 0.75},
    "standard": {"timeout_seconds": 5, "retry_attempts": 3, "retry_backoff_seconds": 1.5},
    "deep": {"timeout_seconds": 8, "retry_attempts": 4, "retry_backoff_seconds": 2.0},
}

# Risk scoring customization.
ASSET_CRITICALITY_RULES = {
    "jenkins": 9,
    "database": 9,
    "db": 9,
    "api": 8,
    "email": 10,
    "mail": 10,
    "s3": 5,
    "staging": 4,
    "test": 4,
    "dev": 2,
}

MAINTENANCE_WINDOWS = {
    "critical": "Saturday 2:00AM-2:30AM",
    "high": "Saturday 3:00AM-4:00AM",
    "medium": "Sunday 1:00AM-2:00AM",
    "low": "Next planned maintenance window",
}
