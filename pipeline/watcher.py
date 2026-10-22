"""Watches a pipeline's source folder and transfers each file once it has finished arriving."""

import logging
import os
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from .config import JobSettings
from .gpg import PgpError
from .transfer import Converter, TransferError, list_source_files, transfer_file

log = logging.getLogger(__name__)


class ScanResult(NamedTuple):
    transferred: int
    failed: int
    arriving: int  # seen, but not finished arriving yet


@dataclass
class _Tracked:
    snapshot: tuple[int, int]  # (size, modification time) when last looked at
    unchanged_since: float  # time.monotonic() value since which the file hasn't changed
    retry_at: float = 0.0  # after a failure: don't try again before this time
    reported_in_use: bool = False


class SourceWatcher:
    """Transfers files from the source folder once they have finished arriving.

    A file has finished arriving when its size and modification time haven't changed for
    STABLE_SECONDS and, on Windows, no other program still has it open for writing. A file that
    fails stays in the source folder and is tried again after RETRY_SECONDS, or as soon as it changes.
    """

    def __init__(self, job: JobSettings, converter: Converter):
        self._job = job
        self._converter = converter
        self._tracked: dict[str, _Tracked] = {}
        self._stopping = False

    def run_once(self) -> int:
        """Transfer the files waiting now, and any still arriving. Returns how many failed."""
        transferred = failed = 0
        with self._stop_on_signals():
            while not self._stopping:
                result = self.scan()
                transferred += result.transferred
                failed += result.failed
                if not result.arriving:
                    break
                time.sleep(self._job.poll_seconds)
        log.info("Done: %d transferred, %d failed", transferred, failed)
        return failed

    def watch(self) -> None:
        """Transfer files as they arrive, until stopped with Ctrl+C or a termination signal."""
        log.info("Watching %s for new files. Press Ctrl+C to stop.", self._job.source_dir)
        with self._stop_on_signals():
            while not self._stopping:
                try:
                    self.scan()
                except OSError as exc:  # e.g. the source folder is temporarily unavailable
                    log.error("Could not read %s: %s", self._job.source_dir, exc)
                time.sleep(self._job.poll_seconds)
        log.info("Stopped watching")

    def scan(self) -> ScanResult:
        """Transfer every file in the source folder that has finished arriving."""
        transferred = failed = arriving = 0
        files = list_source_files(self._job)
        for name in self._tracked.keys() - {path.name for path in files}:
            del self._tracked[name]  # transferred, or removed by someone
        for path in files:
            if self._stopping:
                break
            try:
                tracked = self._track(path)
            except FileNotFoundError:
                continue  # removed since the folder was listed
            now = time.monotonic()
            if now < tracked.retry_at:
                continue
            if now - tracked.unchanged_since < self._job.stable_seconds or self._in_use(path, tracked):
                arriving += 1
            elif self._transfer(path):
                transferred += 1
            else:
                tracked.retry_at = now + self._job.retry_seconds
                failed += 1
        return ScanResult(transferred, failed, arriving)

    def _track(self, path: Path) -> _Tracked:
        stat = path.stat()
        snapshot = (stat.st_size, stat.st_mtime_ns)
        tracked = self._tracked.get(path.name)
        if tracked is None or tracked.snapshot != snapshot:
            # New or changed. Count it as unchanged since it was last modified, so a file that was
            # already waiting when the pipeline started is picked up straight away.
            unmodified_for = max(0.0, time.time() - stat.st_mtime)
            if tracked is None and unmodified_for < self._job.stable_seconds:
                log.info("Found %s, waiting for it to finish arriving", path.name)
            tracked = self._tracked[path.name] = _Tracked(snapshot, time.monotonic() - unmodified_for)
        return tracked

    def _in_use(self, path: Path, tracked: _Tracked) -> bool:
        if os.name != "nt" or not _open_for_writing_elsewhere(path):
            return False
        if not tracked.reported_in_use:
            log.info("%s is still open in another program, waiting for it to be closed", path.name)
            tracked.reported_in_use = True
        return True

    def _transfer(self, path: Path) -> bool:
        try:
            output_file = transfer_file(path, self._job, self._converter)
        except (TransferError, PgpError, OSError) as exc:
            log.error("Could not transfer %s: %s", path.name, exc)
            return False
        except Exception:
            log.exception("Unexpected error while transferring %s", path.name)
            return False
        log.info(
            "%s %s to %s and moved the original to the archive",
            self._converter.action, path.name, Path(output_file.parent.name, output_file.name),
        )
        return True

    @contextmanager
    def _stop_on_signals(self):
        """Make Ctrl+C and termination signals stop between files rather than half-way through one."""

        def request_stop(signum, frame):
            log.info("Stopping...")
            self._stopping = True

        previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            yield
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def _open_for_writing_elsewhere(path: Path) -> bool:
    """Windows only: True while another program has the file open for writing.

    Asks Windows to open the file while refusing to share it with writers. Windows denies that while
    a writer has it open, for example a program still saving it or a copy still in progress.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    generic_read, share_read_only, open_existing, error_sharing_violation = 0x80000000, 0x1, 3, 32

    handle = kernel32.CreateFileW(str(path), generic_read, share_read_only, None, open_existing, 0, None)
    if handle == wintypes.HANDLE(-1).value:  # INVALID_HANDLE_VALUE
        return ctypes.get_last_error() == error_sharing_violation
    kernel32.CloseHandle(handle)
    return False
