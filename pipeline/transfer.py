"""Moves one file through a pipeline: encrypt or decrypt it into the output folder, then move the
original to the archive."""

import fnmatch
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Protocol

from .config import JobSettings

log = logging.getLogger(__name__)

PARTIAL_SUFFIX = ".part"


class Converter(Protocol):
    """What a pipeline does to each file. The Encryptor and the Decryptor are the two kinds."""

    action: str  # what the log says was done, e.g. "Encrypted"

    def output_name(self, source_name: str) -> str: ...

    def convert(self, source: Path, output: Path) -> None: ...


class TransferError(Exception):
    """A file could not be transferred."""


def list_source_files(job: JobSettings) -> list[Path]:
    """Files directly inside the source folder whose names match one of the file patterns (not
    case-sensitive), in name order. Hidden files and Office lock files (~$...) are left alone."""
    patterns = [pattern.lower() for pattern in job.file_patterns]
    return sorted(
        path
        for path in job.source_dir.iterdir()
        if not path.name.startswith((".", "~"))
        and any(fnmatch.fnmatchcase(path.name.lower(), pattern) for pattern in patterns)
        and path.is_file()
    )


def transfer_file(source_file: Path, job: JobSettings, converter: Converter) -> Path:
    """Convert source_file into the output folder, then move the original to the archive. Returns the new file.

    The new file is written under a temporary .part name and renamed once complete, so anything
    reading the output folder never sees half a file. Files already in the output folder or the
    archive are never overwritten.
    """
    output_file = job.output_dir / converter.output_name(source_file.name)
    archive_file = job.archive_dir / source_file.name
    done = converter.action.lower()
    if output_file.exists():
        raise TransferError(
            f"{output_file.name} is already in {job.output_dir.name}, so the file was not {done} again. If it "
            f"was already handled, move the original from {job.source_dir.name} to {job.archive_dir} by hand; "
            "otherwise find out why the same name was used twice."
        )
    if archive_file.exists():
        raise TransferError(
            f"{archive_file.name} is already in the archive, so a file with this name was handled before. "
            "Find out why the same name was used twice."
        )

    before = _snapshot(source_file)
    if before[0] == 0:
        raise TransferError("the file is empty")

    partial_file = output_file.with_name(output_file.name + PARTIAL_SUFFIX)
    try:
        converter.convert(source_file, partial_file)
        if _snapshot(source_file) != before:
            raise TransferError(f"the file changed while it was being {done} (it may still have been arriving)")
        _retry_while_locked(os.replace, partial_file, output_file)
    finally:
        _remove_if_present(partial_file)  # after a failure this may hold part of the result

    try:
        _retry_while_locked(shutil.move, source_file, archive_file)
    except OSError as exc:
        raise TransferError(
            f"it was {done} into {job.output_dir.name}, but the original could not be moved to the archive "
            f"({exc}). Move it to {job.archive_dir} by hand."
        ) from exc
    return output_file


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
