"""Tests using real GnuPG with throwaway keys and temporary folders."""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import gnupg

from pipeline.config import PROJECT_DIR, ConfigError, Settings, load_settings
from pipeline.encryptor import (
    CLASSIC_DATA_PACKET,
    COMPATIBLE_PREFERENCES,
    OCB_DATA_PACKET,
    EncryptionError,
    Encryptor,
    create_key_pair,
    data_packet_type,
    import_public_key,
    open_keyring,
    uses_gnupg_only_format,
)
from pipeline.transfer import TransferError, transfer_file
from pipeline.watcher import SourceWatcher

SAMPLE_NAME = "SBI_SBIN55_20261014_0002.txt"
SAMPLE = b"DCR,8.50,13/10/2026,SBIN55,TEST CUSTOMER,,000000000,SBIN0000000,49,10627,INR\n"


def make_key(gpg, name: str, passphrase: str | None = None, gnupg_defaults: bool = False) -> str:
    """Create a quick elliptic-curve key pair and return its fingerprint.

    Like the pipeline's own keys it uses COMPATIBLE_PREFERENCES, unless gnupg_defaults is set to get
    a key like one made by Kleopatra.
    """
    options = {"passphrase": passphrase} if passphrase else {"no_protection": True}
    if not gnupg_defaults:
        options["preferences"] = COMPATIBLE_PREFERENCES
    key = gpg.gen_key(
        gpg.gen_key_input(
            name_real=name,
            name_email=f"{name.lower()}@example.invalid",
            key_type="EDDSA",
            key_curve="ed25519",
            subkey_type="ECDH",
            subkey_curve="cv25519",
            expire_date="0",
            **options,
        )
    )
    assert key.fingerprint, key.stderr
    return key.fingerprint


def open_test_keyring(home: Path, add_cleanup) -> gnupg.GPG:
    """Open a keyring for a test. gpg starts a background agent for it, which is stopped afterwards."""
    gpg = open_keyring(home)
    if shutil.which("gpgconf"):
        add_cleanup(subprocess.run, ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], capture_output=True)
    return gpg


@unittest.skipUnless(shutil.which("gpg"), "GnuPG (gpg) is not installed")
class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keys take a moment to create, so the tests share them. Folder names are kept short because
        # on macOS gpg's socket path inside a keyring folder has a length limit.
        cls.keys_dir = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.keys_dir, ignore_errors=True)
        # The recipient's keyring plays SBI's computer; the pipeline's keyring only gets the public key.
        cls.recipient_gpg = open_test_keyring(cls.keys_dir / "recipient", cls.addClassCleanup)
        cls.recipient = make_key(cls.recipient_gpg, "Recipient")
        cls.pipeline_gpg = open_test_keyring(cls.keys_dir / "pipeline", cls.addClassCleanup)
        cls.pipeline_gpg.import_keys(cls.recipient_gpg.export_keys(cls.recipient))

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.settings = Settings(
            source_dir=self.tmp / "Source",
            sink_dir=self.tmp / "Sink",
            archive_dir=self.tmp / "Source" / "archive",
            gnupg_home=self.keys_dir / "pipeline",
            recipients=(self.recipient,),
            stable_seconds=0,
            poll_seconds=0.1,
        )
        for folder in (self.settings.sink_dir, self.settings.archive_dir):
            folder.mkdir(parents=True)
        self.encryptor = Encryptor(self.pipeline_gpg, self.settings.recipients)

    def fresh_keyring(self) -> gnupg.GPG:
        return open_test_keyring(self.tmp / "fresh", self.addCleanup)

    def add_source_file(self, name: str = SAMPLE_NAME, content: bytes = SAMPLE) -> Path:
        path = self.settings.source_dir / name
        path.write_bytes(content)
        return path

    def decrypt(self, path: Path):
        result = self.recipient_gpg.decrypt_file(str(path))
        self.assertTrue(result.ok, result.status)
        return result

    def test_encrypts_into_sink_and_archives_the_original(self):
        source = self.add_source_file()

        sink_file = transfer_file(source, self.settings, self.encryptor)

        self.assertEqual(sink_file, self.settings.sink_dir / f"{SAMPLE_NAME}.pgp")
        self.assertFalse(source.exists())
        self.assertEqual((self.settings.archive_dir / SAMPLE_NAME).read_bytes(), SAMPLE)
        encrypted = sink_file.read_bytes()
        self.assertNotIn(SAMPLE, encrypted)
        self.assertFalse(encrypted.startswith(b"-----BEGIN PGP"), "output should be binary .pgp, not text")
        self.assertEqual(data_packet_type(encrypted), CLASSIC_DATA_PACKET, "any PGP program must be able to read it")
        self.assertEqual(self.decrypt(sink_file).data, SAMPLE)
        self.assertEqual(list(self.settings.sink_dir.iterdir()), [sink_file], "no .part file should be left")

    def test_never_overwrites_a_file_already_in_sink(self):
        source = self.add_source_file()
        delivered = self.settings.sink_dir / f"{SAMPLE_NAME}.pgp"
        delivered.write_bytes(b"delivered earlier")

        with self.assertRaises(TransferError):
            transfer_file(source, self.settings, self.encryptor)

        self.assertEqual(delivered.read_bytes(), b"delivered earlier")
        self.assertTrue(source.exists())

    def test_never_overwrites_a_file_already_in_the_archive(self):
        source = self.add_source_file()
        archived = self.settings.archive_dir / SAMPLE_NAME
        archived.write_bytes(b"sent earlier")

        with self.assertRaises(TransferError):
            transfer_file(source, self.settings, self.encryptor)

        self.assertEqual(archived.read_bytes(), b"sent earlier")
        self.assertTrue(source.exists())
        self.assertEqual(list(self.settings.sink_dir.iterdir()), [])

    def test_refuses_an_empty_file(self):
        source = self.add_source_file(content=b"")

        with self.assertRaises(TransferError):
            transfer_file(source, self.settings, self.encryptor)

        self.assertTrue(source.exists())

    def test_picks_up_only_files_matching_the_pattern(self):
        self.add_source_file("SBI_SBIN55_20261014_0001.txt")
        self.add_source_file("sbi_sbin55_20261014_0002.TXT")  # the pattern is not case-sensitive
        self.add_source_file("notes.docx")
        self.add_source_file("SBI_SBIN55_20261014_0003.txt.part")  # still being uploaded

        failed = SourceWatcher(self.settings, self.encryptor).run_once()

        self.assertEqual(failed, 0)
        self.assertEqual(
            sorted(path.name for path in self.settings.sink_dir.iterdir()),
            ["SBI_SBIN55_20261014_0001.txt.pgp", "sbi_sbin55_20261014_0002.TXT.pgp"],
        )
        self.assertEqual(
            sorted(path.name for path in self.settings.source_dir.iterdir() if path.is_file()),
            ["SBI_SBIN55_20261014_0003.txt.part", "notes.docx"],
        )

    def test_waits_until_a_file_has_stopped_changing(self):
        watcher = SourceWatcher(replace(self.settings, stable_seconds=1), self.encryptor)
        source = self.add_source_file()

        self.assertEqual(watcher.scan().arriving, 1)
        self.assertTrue(source.exists(), "a file written just now must not be picked up yet")
        time.sleep(1.2)
        self.assertEqual(watcher.scan().transferred, 1)
        self.assertFalse(source.exists())

    def test_a_failed_file_waits_for_its_retry_unless_it_changes(self):
        source = self.add_source_file(content=b"")
        watcher = SourceWatcher(self.settings, self.encryptor)  # retries after 300 seconds by default

        with self.assertLogs("pipeline.watcher", "ERROR") as logs:
            self.assertEqual(watcher.scan().failed, 1)
        self.assertIn("the file is empty", logs.output[0])
        self.assertEqual(watcher.scan(), (0, 0, 0), "a failed file must not be retried straight away")
        source.write_bytes(SAMPLE)
        self.assertEqual(watcher.scan().transferred, 1, "a file that changed is tried again straight away")

    def test_signed_files_verify_for_the_recipient(self):
        # A pipeline keyring that also holds our own signing key, as it would with signing turned on.
        pipeline_gpg = self.fresh_keyring()
        pipeline_gpg.import_keys(self.recipient_gpg.export_keys(self.recipient))
        sender = make_key(pipeline_gpg, "Sender", passphrase="test-passphrase")
        self.recipient_gpg.import_keys(pipeline_gpg.export_keys(sender))
        encryptor = Encryptor(pipeline_gpg, self.settings.recipients, sender, "test-passphrase")
        encryptor.check_keys()

        result = self.decrypt(transfer_file(self.add_source_file(), self.settings, encryptor))

        self.assertEqual(result.data, SAMPLE)
        self.assertTrue(result.valid)
        self.assertEqual(result.pubkey_fingerprint, sender)

    def test_a_missing_recipient_key_is_reported_before_any_file_is_touched(self):
        with self.assertRaises(EncryptionError):
            Encryptor(self.pipeline_gpg, ["0" * 40]).check_keys()
        with self.assertRaises(EncryptionError):
            Encryptor(self.pipeline_gpg, []).check_keys()

    def test_keys_we_create_give_files_any_pgp_program_can_read(self):
        gpg = self.fresh_keyring()
        fingerprint = create_key_pair(gpg, "Created", "created@example.invalid", "a long test passphrase", 2048)

        self.assertFalse(uses_gnupg_only_format(gpg, [fingerprint]))

    def test_a_key_that_would_give_gnupg_only_files_is_refused_unless_allowed(self):
        gpg = self.fresh_keyring()
        kleopatra_style = make_key(gpg, "Kleopatra", gnupg_defaults=True)
        sample = gpg.encrypt(b"x", [kleopatra_style], always_trust=True, armor=False).data
        self.assertEqual(data_packet_type(sample), OCB_DATA_PACKET)

        with self.assertRaises(EncryptionError):
            Encryptor(gpg, [kleopatra_style]).check_keys()
        Encryptor(gpg, [kleopatra_style], allow_gnupg_only_format=True).check_keys()

    def test_importing_a_public_key(self):
        public_key_file = self.tmp / "public.asc"
        public_key_file.write_text(self.recipient_gpg.export_keys(self.recipient))

        self.assertEqual(import_public_key(self.fresh_keyring(), public_key_file), [self.recipient])

    def test_importing_a_private_key_is_refused(self):
        private_key_file = self.tmp / "private.asc"
        private_key_file.write_text(
            self.recipient_gpg.export_keys(self.recipient, secret=True, expect_passphrase=False)
        )
        fresh = self.fresh_keyring()

        with self.assertRaises(EncryptionError):
            import_public_key(fresh, private_key_file)

        self.assertEqual(fresh.list_keys(secret=True), [])


class SettingsTest(unittest.TestCase):
    def load(self, **environment) -> Settings:
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch("pipeline.config.load_dotenv"):
            return load_settings()

    def test_defaults(self):
        settings = self.load()

        self.assertEqual(settings.source_dir, PROJECT_DIR / "Source")
        self.assertEqual(settings.archive_dir, PROJECT_DIR / "Source" / "archive")
        self.assertEqual(settings.recipients, ())

    def test_fingerprints_are_normalised(self):
        settings = self.load(RECIPIENT_FINGERPRINTS="abcd 1234 abcd 1234 abcd 1234 abcd 1234 abcd 1234, " + "F" * 40)

        self.assertEqual(settings.recipients, ("ABCD1234" * 5, "F" * 40))

    def test_short_key_ids_are_refused(self):
        with self.assertRaises(ConfigError):
            self.load(RECIPIENT_FINGERPRINTS="ABCD1234")

    def test_folders_must_differ(self):
        with self.assertRaises(ConfigError):
            self.load(SOURCE_DIR="data", SINK_DIR="data")

    def test_true_false_settings(self):
        self.assertFalse(self.load().allow_gnupg_only_format)
        self.assertTrue(self.load(ALLOW_GNUPG_ONLY_FORMAT="True").allow_gnupg_only_format)
        with self.assertRaises(ConfigError):
            self.load(ALLOW_GNUPG_ONLY_FORMAT="maybe")


@unittest.skipUnless(os.name == "nt", "Windows only")
class WindowsOpenFileTest(unittest.TestCase):
    def test_detects_a_file_still_open_for_writing(self):
        from pipeline.watcher import _open_for_writing_elsewhere

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "arriving.txt"
            with path.open("wb") as writer:
                writer.write(b"half")
                self.assertTrue(_open_for_writing_elsewhere(path))
            self.assertFalse(_open_for_writing_elsewhere(path))
