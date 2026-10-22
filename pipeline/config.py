"""Pipeline settings, read from environment variables and the .env file in the project folder."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent.parent

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# Accepted values for the file format settings. The defaults are what SBI asked for: AES256, no
# compression, ASCII-armored.
CIPHERS = ("AES256", "AES192", "AES128")
COMPRESSIONS = ("none", "zip", "zlib", "bzip2")

# A full key fingerprint: 40 hex characters (v4 keys) or 64 (newer v5/v6 keys).
_FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")


class ConfigError(Exception):
    """A setting is missing or has an invalid value."""


@dataclass(frozen=True)
class Settings:
    source_dir: Path
    sink_dir: Path
    archive_dir: Path
    gnupg_home: Path
    recipients: tuple[str, ...]
    file_pattern: str = "SBI_*.txt"
    gpg_binary: str = "gpg"
    signing_key: str | None = None
    signing_passphrase: str | None = None
    allow_gnupg_only_format: bool = False
    cipher: str = "AES256"
    compression: str = "none"
    armor: bool = True
    stable_seconds: float = 5.0
    poll_seconds: float = 2.0
    retry_seconds: float = 300.0
    log_dir: Path = PROJECT_DIR / "logs"
    log_level: str = "INFO"


def load_settings() -> Settings:
    """Read the settings. A value already set as an environment variable wins over the .env file."""
    load_dotenv(PROJECT_DIR / ".env")

    source_dir = _path("SOURCE_DIR", "Source")
    signing_key = _text("SIGNING_KEY_FINGERPRINT")
    log_level = _text("LOG_LEVEL", "INFO").upper()
    if log_level not in LOG_LEVELS:
        raise ConfigError(f"LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, not {log_level!r}")

    settings = Settings(
        source_dir=source_dir,
        sink_dir=_path("SINK_DIR", "Sink"),
        archive_dir=_path("ARCHIVE_DIR", source_dir / "archive"),
        gnupg_home=_path("GNUPG_HOME", "gnupg_home"),
        recipients=tuple(
            _fingerprint("RECIPIENT_FINGERPRINTS", item)
            for item in _text("RECIPIENT_FINGERPRINTS").split(",")
            if item.strip()
        ),
        file_pattern=_text("FILE_PATTERN", "SBI_*.txt"),
        gpg_binary=_text("GPG_BINARY", "gpg"),
        signing_key=_fingerprint("SIGNING_KEY_FINGERPRINT", signing_key) if signing_key else None,
        signing_passphrase=os.getenv("SIGNING_KEY_PASSPHRASE") or None,
        allow_gnupg_only_format=_flag("ALLOW_GNUPG_ONLY_FORMAT", default=False),
        cipher=_choice("CIPHER_ALGO", CIPHERS, default="AES256"),
        compression=_choice("COMPRESSION", COMPRESSIONS, default="none"),
        armor=_flag("ARMOR", default=True),
        stable_seconds=_seconds("STABLE_SECONDS", 5.0),
        poll_seconds=_seconds("POLL_SECONDS", 2.0, minimum=0.5),
        retry_seconds=_seconds("RETRY_SECONDS", 300.0),
        log_dir=_path("LOG_DIR", "logs"),
        log_level=log_level,
    )
    if len({settings.source_dir, settings.sink_dir, settings.archive_dir}) < 3:
        raise ConfigError("SOURCE_DIR, SINK_DIR and ARCHIVE_DIR must be three different folders")
    return settings


def _text(name: str, default: str = "") -> str:
    return os.getenv(name, "").strip() or default


def _path(name: str, default: str | Path) -> Path:
    """A folder setting. Relative paths are taken from the project folder."""
    path = Path(_text(name) or default).expanduser()
    return path if path.is_absolute() else PROJECT_DIR / path


def _flag(name: str, default: bool) -> bool:
    raw = _text(name).lower()
    if not raw:
        return default
    if raw in ("true", "yes", "1"):
        return True
    if raw in ("false", "no", "0"):
        return False
    raise ConfigError(f"{name} must be true or false, not {raw!r}")


def _choice(name: str, allowed: tuple[str, ...], default: str) -> str:
    """A setting that must be one of the allowed values (not case-sensitive)."""
    raw = _text(name, default)
    for value in allowed:
        if raw.lower() == value.lower():
            return value
    raise ConfigError(f"{name} must be one of {', '.join(allowed)}, not {raw!r}")


def _seconds(name: str, default: float, minimum: float = 0.0) -> float:
    raw = _text(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number of seconds, not {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum:g} seconds")
    return value


def _fingerprint(name: str, value: str) -> str:
    fingerprint = value.replace(" ", "").upper()
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise ConfigError(
            f"{name}: {value.strip()!r} is not a full key fingerprint (40 hexadecimal characters). "
            "Short key IDs and email addresses are not accepted because they can match the wrong key."
        )
    return fingerprint
