"""Moves one file through the pipeline: encrypt it into Sink, then move the original to the archive."""

import fnmatch
import logging
import os
import shutil
import time
from pathlib import Path

from .config import Settings
from .encryptor import Encryptor

log = logging.getLogger(__name__)

ENCRYPTED_SUFFIX = ".pgp"
PARTIAL_SUFFIX = ".part"


class TransferError(Exception):
    """A file could not be transferred."""


def list_source_files(settings: Settings) -> list[Path]:
    """Files directly inside Source whose names match FILE_PATTERN (not case-sensitive), in name order."""
    pattern = settings.file_pattern.lower()
    return sorted(
        path
        for path in settings.source_dir.iterdir()
        if fnmatch.fnmatchcase(path.name.lower(), pattern) and path.is_file()
    )


def transfer_file(source_file: Path, settings: Settings, encryptor: Encryptor) -> Path:
    """Encrypt source_file into Sink, then move the original to the archive. Returns the encrypted file.

    The encrypted file is written under a temporary .part name and renamed once complete, so anything
    reading Sink never sees half a file. Files already in Sink or the archive are never overwritten.
    """
    sink_file = settings.sink_dir / (source_file.name + ENCRYPTED_SUFFIX)
    archive_file = settings.archive_dir / source_file.name
    if sink_file.exists():
        raise TransferError(
            f"{sink_file.name} is already in Sink, so the file was not encrypted again. If it was already "
            f"delivered, move the original from Source to {settings.archive_dir} by hand; otherwise find out "
            "why the same name was used twice."
        )
    if archive_file.exists():
        raise TransferError(
            f"{archive_file.name} is already in the archive, so a file with this name was sent before. "
            "Find out why the same name was used twice."
        )

    before = _snapshot(source_file)
    if before[0] == 0:
        raise TransferError("the file is empty")

    partial_file = sink_file.with_name(sink_file.name + PARTIAL_SUFFIX)
    try:
        encryptor.encrypt_file(source_file, partial_file)
        if _snapshot(source_file) != before:
            raise TransferError("the file changed while it was being encrypted (it may still have been arriving)")
        _retry_while_locked(os.replace, partial_file, sink_file)
    finally:
        _remove_if_present(partial_file)

    try:
        _retry_while_locked(shutil.move, source_file, archive_file)
    except OSError as exc:
        raise TransferError(
            f"it was encrypted into Sink, but the original could not be moved to the archive ({exc}). "
            f"Move it to {settings.archive_dir} by hand."
        ) from exc
    return sink_file


def _snapshot(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns


def _retry_while_locked(action, *args, attempts: int = 5):
    """Run a file operation, retrying for up to 10 seconds while the file is locked.

    On Windows, antivirus and backup software often hold a new file open for a moment.
    """
    for attempt in range(1, attempts + 1):
        try:
            return action(*args)
        except PermissionError:
            if attempt == attempts:
                raise
            time.sleep(attempt)


def _remove_if_present(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:  # e.g. locked by a virus scanner; gpg overwrites it on the next attempt
        log.warning("Could not remove %s: %s", path.name, exc)
