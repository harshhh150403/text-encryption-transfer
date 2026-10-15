"""Encrypts files that arrive in the Source folder with PGP and delivers them to the Sink folder.

    python main.py          watch Source and encrypt each file as it arrives (Ctrl+C to stop)
    python main.py --once   encrypt the files waiting in Source now, then exit
"""

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler

from filelock import FileLock, Timeout

from pipeline.config import ConfigError, Settings, load_settings
from pipeline.encryptor import EncryptionError, Encryptor, open_keyring
from pipeline.watcher import SourceWatcher

log = logging.getLogger("pipeline")

# Exit codes
OK = 0
FAILED = 1  # a file could not be transferred, or another copy is already running
SETUP_ERROR = 2  # settings, GnuPG or keys need fixing before anything can run


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt files from Source with PGP and deliver them to Sink.")
    parser.add_argument("--once", action="store_true", help="encrypt the files waiting in Source now, then exit")
    args = parser.parse_args()

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return SETUP_ERROR
    setup_logging(settings)

    if not settings.source_dir.is_dir():
        log.error("The Source folder %s does not exist. Check SOURCE_DIR in .env.", settings.source_dir)
        return SETUP_ERROR
    settings.sink_dir.mkdir(parents=True, exist_ok=True)
    settings.archive_dir.mkdir(parents=True, exist_ok=True)

    # Only one copy may work on these folders at a time, so a manual --once run can't race the watcher.
    try:
        with FileLock(settings.archive_dir / ".pipeline.lock").acquire(timeout=0):
            return run(settings, once=args.once)
    except Timeout:
        log.error("Another copy of the pipeline is already running for %s", settings.source_dir)
        return FAILED


def run(settings: Settings, once: bool) -> int:
    try:
        encryptor = Encryptor(
            open_keyring(settings.gnupg_home, settings.gpg_binary),
            settings.recipients,
            settings.signing_key,
            settings.signing_passphrase,
            settings.allow_gnupg_only_format,
        )
        encryptor.check_keys()
    except EncryptionError as exc:
        log.error("%s", exc)
        return SETUP_ERROR

    log.info("Source: %s | Sink: %s | Archive: %s", settings.source_dir, settings.sink_dir, settings.archive_dir)
    watcher = SourceWatcher(settings, encryptor)
    if once:
        return FAILED if watcher.run_once() else OK
    watcher.watch()
    return OK


def setup_logging(settings: Settings) -> None:
    """Log to the console and to logs/pipeline.log (a new file every 5 MB, the last 5 kept)."""
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=[
            logging.StreamHandler(),
            RotatingFileHandler(
                settings.log_dir / "pipeline.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8"
            ),
        ],
    )
    logging.getLogger("gnupg").setLevel(logging.WARNING)  # python-gnupg's own debug output is very chatty


if __name__ == "__main__":
    sys.exit(main())
