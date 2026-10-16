"""Environment-driven configuration, validated once at startup."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MIN_SECRET_LENGTH = 32
_TRUE = {"1", "true", "yes"}
_FALSE = {"0", "false", "no", ""}


class ConfigError(ValueError):
    """Raised when the environment is missing or has invalid settings.

    Messages name the offending variables but never include their values.
    """


def _parse_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name} must be one of 1/true/yes/0/false/no.")


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated application settings."""

    secret_key: str = field(repr=False)
    owner_email: str
    base_url: str
    mock_mode: bool
    timezone: ZoneInfo
    db_path: Path
    google_client_id: str | None = None
    google_client_secret: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Build settings from an environment mapping (default: os.environ).

        Raises:
            ConfigError: if required variables are missing or any value is
                invalid. All problems found are reported together.
        """
        env = os.environ if env is None else env
        problems: list[str] = []

        def get(name: str) -> str:
            return env.get(name, "").strip()

        mock_mode = False
        try:
            mock_mode = _parse_bool("KYTE_MOCK", env.get("KYTE_MOCK", "0"))
        except ConfigError as exc:
            problems.append(str(exc))

        required = ["KYTE_SECRET_KEY", "KYTE_OWNER_EMAIL"]
        if not mock_mode:
            required += ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]
        missing = [name for name in required if not get(name)]
        if missing:
            problems.append(
                "Missing required environment variables: " + ", ".join(missing)
            )

        secret_key = get("KYTE_SECRET_KEY")
        if secret_key and len(secret_key) < MIN_SECRET_LENGTH:
            problems.append(
                f"KYTE_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters."
            )

        owner_email = get("KYTE_OWNER_EMAIL").lower()
        if owner_email and "@" not in owner_email:
            problems.append("KYTE_OWNER_EMAIL must be an email address.")

        base_url = (get("KYTE_BASE_URL") or "http://localhost:8000").rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            problems.append("KYTE_BASE_URL must start with http:// or https://.")

        tz_name = get("KYTE_TIMEZONE") or "UTC"
        timezone = ZoneInfo("UTC")
        try:
            timezone = ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            problems.append("KYTE_TIMEZONE must be an IANA name like Europe/Paris.")

        if problems:
            raise ConfigError(" ".join(problems))

        return cls(
            secret_key=secret_key,
            owner_email=owner_email,
            base_url=base_url,
            mock_mode=mock_mode,
            timezone=timezone,
            db_path=Path(get("KYTE_DB_PATH") or "kyte.db"),
            google_client_id=get("GOOGLE_CLIENT_ID") or None,
            google_client_secret=get("GOOGLE_CLIENT_SECRET") or None,
        )
