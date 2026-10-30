"""Pipeline settings, read from environment variables and the .env file in the project folder.

The encryption and decryption pipelines each read only their own settings, so a mistake in one
pipeline's settings can't stop the other. Both check that the two pipelines don't share folders.
"""

import io
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values, load_dotenv

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
class JobSettings:
    """One pipeline's folders, which files it picks up, and its timing: everything the watcher needs."""

    source_dir: Path
    output_dir: Path
    archive_dir: Path
    file_patterns: tuple[str, ...]
    stable_seconds: float = 5.0
    poll_seconds: float = 2.0
    retry_seconds: float = 300.0


@dataclass(frozen=True)
class EncryptionSettings:
    """Files we send to SBI: encrypted with SBI's public key."""

    job: JobSettings
    gnupg_home: Path
    recipients: tuple[str, ...]
    gpg_binary: str = "gpg"
    signing_key: str | None = None
    signing_passphrase: str | None = None
    allow_gnupg_only_format: bool = False
    cipher: str = "AES256"
    compression: str = "none"
    armor: bool = True
    file_name: str = "{name}.pgp.txt"


@dataclass(frozen=True)
class DecryptionSettings:
    """Files SBI sends us: decrypted with our private key."""

    job: JobSettings
    gnupg_home: Path
    passphrase: str | None = None
    gpg_binary: str = "gpg"


@dataclass(frozen=True)
class LogSettings:
    log_dir: Path
    log_level: str = "INFO"


def load_encryption_settings() -> EncryptionSettings:
    """Read the encryption pipeline's settings. An environment variable wins over the .env file."""
    _load_env_file()
    _check_folders()
    signing_key = _text("SIGNING_KEY_FINGERPRINT")
    return EncryptionSettings(
        job=_job(_encryption_folders(), "FILE_PATTERN", "SBI_*.txt"),
        gnupg_home=_path("GNUPG_HOME", "gnupg_home"),
        recipients=tuple(
            _fingerprint("RECIPIENT_FINGERPRINTS", item)
            for item in _text("RECIPIENT_FINGERPRINTS").split(",")
            if item.strip()
        ),
        gpg_binary=_text("GPG_BINARY", "gpg"),
        signing_key=_fingerprint("SIGNING_KEY_FINGERPRINT", signing_key) if signing_key else None,
        signing_passphrase=os.getenv("SIGNING_KEY_PASSPHRASE") or None,
        allow_gnupg_only_format=_flag("ALLOW_GNUPG_ONLY_FORMAT", default=False),
        cipher=_choice("CIPHER_ALGO", CIPHERS, default="AES256"),
        compression=_choice("COMPRESSION", COMPRESSIONS, default="none"),
        armor=_flag("ARMOR", default=True),
        file_name=_file_name_pattern("ENCRYPTED_FILE_NAME", "{name}.pgp.txt"),
    )


def load_decryption_settings() -> DecryptionSettings:
    """Read the decryption pipeline's settings. An environment variable wins over the .env file."""
    _load_env_file()
    _check_folders()
    return DecryptionSettings(
        job=_job(_decryption_folders(), "DECRYPT_FILE_PATTERN", "*.pgp, *.gpg, *.asc, *.pgp.txt"),
        gnupg_home=_path("DECRYPT_GNUPG_HOME", "gnupg_home_decrypt"),
        passphrase=os.getenv("DECRYPT_KEY_PASSPHRASE") or None,  # as written: spaces can be part of it
        gpg_binary=_text("GPG_BINARY", "gpg"),
    )


def load_log_settings() -> LogSettings:
    _load_env_file()
    log_level = _text("LOG_LEVEL", "INFO").upper()
    if log_level not in LOG_LEVELS:
        raise ConfigError(f"LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, not {log_level!r}")
    return LogSettings(log_dir=_path("LOG_DIR", "logs"), log_level=log_level)


def how_to_write_in_env_file(value: str) -> str | None:
    """How to write value after the = in .env so it is read back exactly: "as is", "in single quotes",
    or None if neither works (it starts with a quote, or needs quotes and contains a single quote)."""
    dotenv_log = logging.getLogger("dotenv.main")
    level = dotenv_log.level
    dotenv_log.setLevel(logging.ERROR)  # it warns about lines it can't read, which is what is being tried
    try:
        for form, line in (("as is", f"X={value}"), ("in single quotes", f"X='{value}'")):
            if dotenv_values(stream=io.StringIO(line + "\n"), interpolate=False).get("X") == value:
                return form
        return None
    finally:
        dotenv_log.setLevel(level)


def _load_env_file() -> None:
    # interpolate=False: take every value literally. Otherwise "${...}" in a value, such as in a
    # passphrase, would be replaced by an environment variable.
    load_dotenv(PROJECT_DIR / ".env", interpolate=False)


def _encryption_folders() -> tuple[Path, Path, Path]:
    source_dir = _path("SOURCE_DIR", "Source")
    return source_dir, _path("SINK_DIR", "Sink"), _path("ARCHIVE_DIR", source_dir / "archive")


def _decryption_folders() -> tuple[Path, Path, Path]:
    source_dir = _path("DECRYPT_SOURCE_DIR", "Inbound")
    return source_dir, _path("DECRYPT_DESTINATION_DIR", "Decrypted"), _path("DECRYPT_ARCHIVE_DIR", source_dir / "archive")


def _check_folders() -> None:
    """Each pipeline needs three different folders, and the two pipelines must not share folders or keyrings."""
    encryption, decryption = _encryption_folders(), _decryption_folders()
    if len(set(encryption)) < 3:
        raise ConfigError("SOURCE_DIR, SINK_DIR and ARCHIVE_DIR must be three different folders")
    if len(set(decryption)) < 3:
        raise ConfigError("DECRYPT_SOURCE_DIR, DECRYPT_DESTINATION_DIR and DECRYPT_ARCHIVE_DIR must be three different folders")
    shared = set(encryption) & set(decryption)
    if shared:
        raise ConfigError(
            f"The encryption and decryption pipelines must not share folders ({', '.join(map(str, shared))}). "
            "For example, decrypted files landing in SOURCE_DIR would be encrypted and sent back to SBI."
        )
    if _path("GNUPG_HOME", "gnupg_home") == _path("DECRYPT_GNUPG_HOME", "gnupg_home_decrypt"):
        raise ConfigError(
            "GNUPG_HOME and DECRYPT_GNUPG_HOME must be different folders: our private key belongs only in "
            "the decryption pipeline's keyring."
        )


def _job(folders: tuple[Path, Path, Path], pattern_setting: str, default_patterns: str) -> JobSettings:
    source_dir, output_dir, archive_dir = folders
    return JobSettings(
        source_dir=source_dir,
        output_dir=output_dir,
        archive_dir=archive_dir,
        file_patterns=tuple(
            pattern.strip() for pattern in _text(pattern_setting, default_patterns).split(",") if pattern.strip()
        ),
        stable_seconds=_seconds("STABLE_SECONDS", 5.0),
        poll_seconds=_seconds("POLL_SECONDS", 2.0, minimum=0.5),
        retry_seconds=_seconds("RETRY_SECONDS", 300.0),
    )


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


def _file_name_pattern(name: str, default: str) -> str:
    """A pattern for naming a file after another: {name} is the original name without its extension,
    {ext} the extension (such as .txt)."""
    pattern = _text(name, default)
    try:
        example = pattern.format(name="SBI_X", ext=".txt")
    except (KeyError, IndexError, ValueError):
        example = None
    if example is None or "{name}" not in pattern or any(char in example for char in '/\\:*?"<>|'):
        raise ConfigError(
            f"{name} must contain {{name}} (the original name without its extension) and may contain {{ext}} "
            f"(its extension), as in {default}. {pattern!r} is not valid."
        )
    return pattern


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
