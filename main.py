"""Runs one of the two pipelines.

    python main.py                  encryption: watch Source and encrypt each file for SBI as it arrives
    python main.py --once           encryption: encrypt the files waiting now, then exit
    python main.py decrypt          decryption: watch the inbound folder and decrypt each file from SBI
    python main.py decrypt --once   decryption: decrypt the files waiting now, then exit

Each pipeline has its own settings, folders, keyring and log file, and both can run at the same time.
Stop a watching pipeline with Ctrl+C.
"""

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler

from filelock import FileLock, Timeout

from pipeline.config import (
    ConfigError,
    DecryptionSettings,
    EncryptionSettings,
    LogSettings,
    load_decryption_settings,
    load_encryption_settings,
    load_log_settings,
)
from pipeline.decryptor import Decryptor
from pipeline.encryptor import Encryptor
from pipeline.gpg import PgpError, open_keyring
from pipeline.watcher import SourceWatcher

log = logging.getLogger("pipeline")

# Exit codes
OK = 0
FAILED = 1  # a file could not be transferred, or another copy is already running
SETUP_ERROR = 2  # settings, GnuPG or keys need fixing before anything can run


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt files for SBI, or decrypt files from SBI.")
    parser.add_argument(
        "pipeline", nargs="?", choices=("encrypt", "decrypt"), default="encrypt",
        help="which pipeline to run (default: encrypt)",
    )
    parser.add_argument("--once", action="store_true", help="process the files waiting now, then exit")
    args = parser.parse_args()

    try:
        log_settings = load_log_settings()
        settings = load_encryption_settings() if args.pipeline == "encrypt" else load_decryption_settings()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return SETUP_ERROR
    setup_logging(log_settings, args.pipeline)

    job = settings.job
    if not job.source_dir.is_dir():
        setting = "SOURCE_DIR" if args.pipeline == "encrypt" else "DECRYPT_SOURCE_DIR"
        log.error("The source folder %s does not exist. Check %s in .env.", job.source_dir, setting)
        return SETUP_ERROR
    job.output_dir.mkdir(parents=True, exist_ok=True)
    job.archive_dir.mkdir(parents=True, exist_ok=True)

    # Only one copy may work on these folders at a time, so a manual --once run can't race the watcher.
    try:
        with FileLock(job.archive_dir / ".pipeline.lock").acquire(timeout=0):
            return run(settings, once=args.once)
    except Timeout:
        name = "encryption" if args.pipeline == "encrypt" else "decryption"
        log.error("Another copy of the %s pipeline is already running for %s", name, job.source_dir)
        return FAILED


def run(settings: EncryptionSettings | DecryptionSettings, once: bool) -> int:
    try:
        if isinstance(settings, DecryptionSettings):
            converter = Decryptor(open_keyring(settings.gnupg_home, settings.gpg_binary), settings.passphrase)
            output_label = "Destination"
        else:
            converter = Encryptor(
                open_keyring(settings.gnupg_home, settings.gpg_binary),
                settings.recipients,
                settings.signing_key,
                settings.signing_passphrase,
                cipher=settings.cipher,
                compression=settings.compression,
                armor=settings.armor,
                file_name=settings.file_name,
                allow_gnupg_only_format=settings.allow_gnupg_only_format,
            )
            output_label = "Sink"
        converter.check_keys()
    except PgpError as exc:
        log.error("%s", exc)
        return SETUP_ERROR

    job = settings.job
    log.info("Source: %s | %s: %s | Archive: %s", job.source_dir, output_label, job.output_dir, job.archive_dir)
    watcher = SourceWatcher(job, converter)
    if once:
        return FAILED if watcher.run_once() else OK
    watcher.watch()
    return OK


def setup_logging(settings: LogSettings, pipeline: str) -> None:
    """Log to the console and to logs/<pipeline>.log (a new file every 5 MB, the last 5 kept)."""
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=[
            logging.StreamHandler(),
            RotatingFileHandler(
                settings.log_dir / f"{pipeline}.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8"
            ),
        ],
    )
    # python-gnupg logs every gpg failure as a warning too; the pipeline's own message already says
    # what went wrong, including gpg's explanation.
    logging.getLogger("gnupg").setLevel(logging.ERROR)


if __name__ == "__main__":
    sys.exit(main())
