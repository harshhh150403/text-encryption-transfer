"""Tests using real GnuPG with throwaway keys and temporary folders."""

import base64
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import gnupg

from pipeline.config import (
    PROJECT_DIR,
    ConfigError,
    DecryptionSettings,
    EncryptionSettings,
    JobSettings,
    how_to_write_in_env_file,
    load_decryption_settings,
    load_encryption_settings,
)
from pipeline.decryptor import Decryptor
from pipeline.encryptor import CLASSIC_DATA_PACKET, OCB_DATA_PACKET, Encryptor, data_packet_type, uses_gnupg_only_format
from pipeline.gpg import (
    COMPATIBLE_PREFERENCES,
    PgpError,
    create_key_pair,
    import_public_key,
    key_expiry,
    key_problem,
    open_keyring,
    stop_gpg_agent,
)
from pipeline.transfer import TransferError, transfer_file
from pipeline.watcher import SourceWatcher

SAMPLE_NAME = "SBI_SBIN55_20261014_0002.txt"
SAMPLE = b"DCR,8.50,13/10/2026,SBIN55,TEST CUSTOMER,,000000000,SBIN0000000,49,10627,INR\n"
PASSPHRASE = "our test passphrase"

# OpenPGP's numbers for the algorithms (RFC 4880, 9.2 and 9.3), as gpg reports them.
AES128, AES256 = 7, 9
ZLIB = 2


def dearmor(armored: bytes) -> bytes:
    """The binary OpenPGP data inside an ASCII-armored message."""
    lines = armored.decode("ascii").splitlines()
    body = lines[lines.index("") + 1 : -1]  # between the blank line after the header and the END line
    return base64.b64decode("".join(line for line in body if not line.startswith("=")))  # "=..." is a checksum


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
    add_cleanup(stop_gpg_agent, home)
    return gpg


def temporary_folder(test) -> Path:
    """A new temporary folder, deleted after the test. Its path is short because on macOS gpg's
    socket path inside a keyring folder has a length limit."""
    folder = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, folder, ignore_errors=True)
    return folder


@unittest.skipUnless(shutil.which("gpg"), "GnuPG (gpg) is not installed")
class EncryptionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keys take a moment to create, so the tests share them.
        cls.keys_dir = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.keys_dir, ignore_errors=True)
        # The recipient's keyring plays SBI's computer; the pipeline's keyring only gets the public key.
        cls.recipient_gpg = open_test_keyring(cls.keys_dir / "recipient", cls.addClassCleanup)
        cls.recipient = make_key(cls.recipient_gpg, "Recipient")
        cls.pipeline_gpg = open_test_keyring(cls.keys_dir / "pipeline", cls.addClassCleanup)
        cls.pipeline_gpg.import_keys(cls.recipient_gpg.export_keys(cls.recipient))

    def setUp(self):
        self.tmp = temporary_folder(self)
        self.job = JobSettings(
            source_dir=self.tmp / "Source",
            output_dir=self.tmp / "Sink",
            archive_dir=self.tmp / "Source" / "archive",
            file_patterns=("SBI_*.txt",),
            stable_seconds=0,
            poll_seconds=0.1,
        )
        for folder in (self.job.output_dir, self.job.archive_dir):
            folder.mkdir(parents=True)
        self.encryptor = Encryptor(self.pipeline_gpg, [self.recipient])

    def fresh_keyring(self) -> gnupg.GPG:
        return open_test_keyring(self.tmp / "fresh", self.addCleanup)

    def add_source_file(self, name: str = SAMPLE_NAME, content: bytes = SAMPLE) -> Path:
        path = self.job.source_dir / name
        path.write_bytes(content)
        return path

    def decrypt(self, path: Path):
        result = self.recipient_gpg.decrypt_file(str(path))
        self.assertTrue(result.ok, result.status)
        return result

    def cipher_used(self, path: Path) -> int:
        """The number of the cipher the file was encrypted with, as gpg reports it when decrypting."""
        return int(re.search(r"DECRYPTION_INFO \d+ (\d+)", self.decrypt(path).stderr).group(1))

    def packets(self, path: Path) -> str:
        """gpg's list of the packets in an encrypted file, decrypted with the recipient's key."""
        return subprocess.run(
            ["gpg", "--homedir", str(self.keys_dir / "recipient"), "--batch", "--list-packets", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout

    def test_encrypts_into_sink_and_archives_the_original(self):
        source = self.add_source_file()

        sink_file = transfer_file(source, self.job, self.encryptor)

        self.assertEqual(sink_file, self.job.output_dir / f"{SAMPLE_NAME}.pgp")
        self.assertFalse(source.exists())
        self.assertEqual((self.job.archive_dir / SAMPLE_NAME).read_bytes(), SAMPLE)
        encrypted = sink_file.read_bytes()
        self.assertNotIn(SAMPLE, encrypted)
        self.assertEqual(
            data_packet_type(dearmor(encrypted)), CLASSIC_DATA_PACKET, "any PGP program must be able to read it"
        )
        self.assertEqual(self.decrypt(sink_file).data, SAMPLE)
        self.assertEqual(list(self.job.output_dir.iterdir()), [sink_file], "no .part file should be left")

    def test_files_are_in_the_format_sbi_asked_for(self):
        sink_file = transfer_file(self.add_source_file(), self.job, self.encryptor)

        self.assertTrue(sink_file.read_bytes().startswith(b"-----BEGIN PGP MESSAGE-----"), "ASCII-armored")
        self.assertEqual(self.cipher_used(sink_file), AES256)
        packets = self.packets(sink_file)
        self.assertIn(":literal data packet:", packets)
        self.assertNotIn(":compressed packet:", packets, "no compression")
        self.assertNotIn(":onepass_sig packet:", packets, "no signature")
        self.assertNotIn(":signature packet:", packets, "no signature")

    def test_format_settings_are_used(self):
        encryptor = Encryptor(self.pipeline_gpg, [self.recipient], cipher="AES128", compression="zlib", armor=False)

        sink_file = transfer_file(self.add_source_file(), self.job, encryptor)

        self.assertFalse(sink_file.read_bytes().startswith(b"-----BEGIN"), "binary")
        self.assertEqual(self.cipher_used(sink_file), AES128)
        self.assertIn(f":compressed packet: algo={ZLIB}", self.packets(sink_file))
        self.assertEqual(self.decrypt(sink_file).data, SAMPLE)

    def test_never_overwrites_a_file_already_in_sink(self):
        source = self.add_source_file()
        delivered = self.job.output_dir / f"{SAMPLE_NAME}.pgp"
        delivered.write_bytes(b"delivered earlier")

        with self.assertRaises(TransferError):
            transfer_file(source, self.job, self.encryptor)

        self.assertEqual(delivered.read_bytes(), b"delivered earlier")
        self.assertTrue(source.exists())

    def test_never_overwrites_a_file_already_in_the_archive(self):
        source = self.add_source_file()
        archived = self.job.archive_dir / SAMPLE_NAME
        archived.write_bytes(b"sent earlier")

        with self.assertRaises(TransferError):
            transfer_file(source, self.job, self.encryptor)

        self.assertEqual(archived.read_bytes(), b"sent earlier")
        self.assertTrue(source.exists())
        self.assertEqual(list(self.job.output_dir.iterdir()), [])

    def test_refuses_an_empty_file(self):
        source = self.add_source_file(content=b"")

        with self.assertRaises(TransferError):
            transfer_file(source, self.job, self.encryptor)

        self.assertTrue(source.exists())

    def test_picks_up_only_files_matching_the_pattern(self):
        self.add_source_file("SBI_SBIN55_20261014_0001.txt")
        self.add_source_file("sbi_sbin55_20261014_0002.TXT")  # the pattern is not case-sensitive
        self.add_source_file("notes.docx")
        self.add_source_file("SBI_SBIN55_20261014_0003.txt.part")  # still being uploaded

        failed = SourceWatcher(self.job, self.encryptor).run_once()

        self.assertEqual(failed, 0)
        self.assertEqual(
            sorted(path.name for path in self.job.output_dir.iterdir()),
            ["SBI_SBIN55_20261014_0001.txt.pgp", "sbi_sbin55_20261014_0002.TXT.pgp"],
        )
        self.assertEqual(
            sorted(path.name for path in self.job.source_dir.iterdir() if path.is_file()),
            ["SBI_SBIN55_20261014_0003.txt.part", "notes.docx"],
        )

    def test_waits_until_a_file_has_stopped_changing(self):
        watcher = SourceWatcher(replace(self.job, stable_seconds=1), self.encryptor)
        source = self.add_source_file()

        self.assertEqual(watcher.scan().arriving, 1)
        self.assertTrue(source.exists(), "a file written just now must not be picked up yet")
        time.sleep(1.2)
        self.assertEqual(watcher.scan().transferred, 1)
        self.assertFalse(source.exists())

    def test_a_failed_file_waits_for_its_retry_unless_it_changes(self):
        source = self.add_source_file(content=b"")
        watcher = SourceWatcher(self.job, self.encryptor)  # retries after 300 seconds by default

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
        encryptor = Encryptor(pipeline_gpg, [self.recipient], sender, "test-passphrase")
        encryptor.check_keys()

        result = self.decrypt(transfer_file(self.add_source_file(), self.job, encryptor))

        self.assertEqual(result.data, SAMPLE)
        self.assertTrue(result.valid)
        self.assertEqual(result.pubkey_fingerprint, sender)

    def test_a_missing_recipient_key_is_reported_before_any_file_is_touched(self):
        with self.assertRaises(PgpError):
            Encryptor(self.pipeline_gpg, ["0" * 40]).check_keys()
        with self.assertRaises(PgpError):
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

        with self.assertRaises(PgpError):
            Encryptor(gpg, [kleopatra_style]).check_keys()
        Encryptor(gpg, [kleopatra_style], allow_gnupg_only_format=True).check_keys()

    def test_importing_a_public_key(self):
        public_key_file = self.tmp / "public.asc"
        public_key_file.write_text(self.recipient_gpg.export_keys(self.recipient))

        self.assertEqual(import_public_key(self.fresh_keyring(), public_key_file), [self.recipient])

    def test_importing_a_file_with_several_keys(self):
        fresh = self.fresh_keyring()
        other = make_key(fresh, "Other")
        both = self.tmp / "both.txt"  # SBI's file is named .txt, which works as long as it holds the keys
        both.write_text(self.recipient_gpg.export_keys(self.recipient) + fresh.export_keys(other))

        importer = open_test_keyring(self.tmp / "importer", self.addCleanup)
        self.assertEqual(import_public_key(importer, both), sorted([self.recipient, other]))

    def test_importing_a_private_key_is_refused(self):
        private_key_file = self.tmp / "private.asc"
        private_key_file.write_text(
            self.recipient_gpg.export_keys(self.recipient, secret=True, expect_passphrase=False)
        )
        fresh = self.fresh_keyring()

        with self.assertRaises(PgpError):
            import_public_key(fresh, private_key_file)

        self.assertEqual(fresh.list_keys(secret=True), [])


@unittest.skipUnless(shutil.which("gpg"), "GnuPG (gpg) is not installed")
class DecryptionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys_dir = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.keys_dir, ignore_errors=True)
        # Our keyring holds our private key, protected by a passphrase, as on the server.
        cls.our_gpg = open_test_keyring(cls.keys_dir / "ours", cls.addClassCleanup)
        cls.our_key = make_key(cls.our_gpg, "Ours", passphrase=PASSPHRASE)
        # SBI's keyring has only our public key, plus a key of someone else's.
        cls.sbi_gpg = open_test_keyring(cls.keys_dir / "sbi", cls.addClassCleanup)
        cls.sbi_gpg.import_keys(cls.our_gpg.export_keys(cls.our_key))
        cls.stranger = make_key(cls.sbi_gpg, "Stranger")

    def setUp(self):
        self.tmp = temporary_folder(self)
        self.job = JobSettings(
            source_dir=self.tmp / "Inbound",
            output_dir=self.tmp / "Decrypted",
            archive_dir=self.tmp / "Inbound" / "archive",
            file_patterns=("*.pgp", "*.gpg", "*.asc"),
            stable_seconds=0,
            poll_seconds=0.1,
        )
        for folder in (self.job.output_dir, self.job.archive_dir):
            folder.mkdir(parents=True)
        self.decryptor = Decryptor(self.our_gpg, PASSPHRASE)

    def encrypted_by_sbi(self, content: bytes = SAMPLE, recipient: str | None = None, armor: bool = True) -> bytes:
        """content encrypted the way SBI sends files: for our public key, AES256, not compressed."""
        result = self.sbi_gpg.encrypt(
            content, recipient or self.our_key, always_trust=True, armor=armor,
            extra_args=["--cipher-algo", "AES256", "--compress-algo", "none"],
        )
        self.assertTrue(result.ok, result.status)
        return result.data

    def sbi_sends(self, name: str, content: bytes | None = None) -> Path:
        path = self.job.source_dir / name
        path.write_bytes(self.encrypted_by_sbi() if content is None else content)
        return path

    def test_decrypts_into_the_destination_and_archives_the_encrypted_original(self):
        source = self.sbi_sends("SBI_RESPONSE_0001.txt.pgp")
        encrypted = source.read_bytes()

        output = transfer_file(source, self.job, self.decryptor)

        self.assertEqual(output, self.job.output_dir / "SBI_RESPONSE_0001.txt")
        self.assertEqual(output.read_bytes(), SAMPLE)
        self.assertFalse(source.exists())
        self.assertEqual((self.job.archive_dir / source.name).read_bytes(), encrypted, "archived still encrypted")
        self.assertEqual(list(self.job.output_dir.iterdir()), [output], "no .part file should be left")

    def test_binary_files_are_decrypted_too(self):
        source = self.sbi_sends("SBI_RESPONSE_0001.txt.gpg", self.encrypted_by_sbi(armor=False))

        self.assertEqual(transfer_file(source, self.job, self.decryptor).read_bytes(), SAMPLE)

    def test_the_decrypted_file_is_named_without_the_encryption_extension(self):
        name = self.decryptor.output_name
        self.assertEqual(name("SBI_0001.txt.pgp"), "SBI_0001.txt")
        self.assertEqual(name("SBI_0001.txt.GPG"), "SBI_0001.txt")
        self.assertEqual(name("SBI_0001.asc"), "SBI_0001")
        self.assertEqual(name("SBI_0001.txt"), "SBI_0001.txt")  # nothing to remove: it lands in another folder

    def test_refused_files_stay_where_they_are_and_leave_nothing_decrypted_behind(self):
        good = self.encrypted_by_sbi()
        not_encrypted = "it is not a PGP-encrypted file, or it is damaged"
        cases = {
            "for_someone_else.pgp": (self.encrypted_by_sbi(recipient=self.stranger), "not encrypted for our key"),
            "plain_text.pgp": (SAMPLE, not_encrypted),
            "damaged.pgp": (good[: len(good) // 2], "damaged"),
            # gpg writes out the text of a signed-only message before reporting it isn't encrypted
            "signed_only.pgp": (self.sbi_gpg.sign(SAMPLE, keyid=self.stranger).data, not_encrypted),
            "password.pgp": (
                self.sbi_gpg.encrypt(SAMPLE, None, symmetric="AES256", passphrase="another password").data,
                "encrypted with a password",
            ),
            # ...even when the password happens to be our passphrase
            "our_passphrase.pgp": (
                self.sbi_gpg.encrypt(SAMPLE, None, symmetric="AES256", passphrase=PASSPHRASE).data,
                "encrypted with a password",
            ),
        }
        for name, (content, reason) in cases.items():
            with self.subTest(name):
                source = self.sbi_sends(name, content)

                with self.assertRaises(PgpError) as raised:
                    transfer_file(source, self.job, self.decryptor)

                self.assertIn(reason, str(raised.exception))
                self.assertTrue(source.exists())
                self.assertEqual(list(self.job.output_dir.iterdir()), [], "nothing decrypted may be left behind")

    def test_a_wrong_passphrase_is_caught_at_startup_even_right_after_the_right_one(self):
        Decryptor(self.our_gpg, PASSPHRASE).check_keys()  # gpg-agent now remembers the right passphrase

        with self.assertRaises(PgpError) as raised:
            Decryptor(self.our_gpg, "not our passphrase").check_keys()
        self.assertIn("passphrase is wrong", str(raised.exception))

    def test_a_missing_passphrase_fails_instead_of_waiting_for_someone_to_type_it(self):
        with self.assertRaises(PgpError) as raised:
            Decryptor(self.our_gpg).check_keys()
        self.assertIn("needs its passphrase", str(raised.exception))

    def test_a_keyring_without_our_private_key_is_refused(self):
        empty = open_test_keyring(self.tmp / "empty", self.addCleanup)

        with self.assertRaises(PgpError) as raised:
            Decryptor(empty, PASSPHRASE).check_keys()
        self.assertIn("no usable private key", str(raised.exception))

    def test_the_watcher_decrypts_matching_files_and_leaves_the_rest(self):
        self.sbi_sends("SBI_RESPONSE_0001.txt.pgp")
        self.sbi_sends("SBI_RESPONSE_0002.asc")
        self.sbi_sends("._SBI_RESPONSE_0003.txt.pgp")  # hidden: e.g. left behind by macOS
        (self.job.source_dir / "readme.txt").write_text("not for the pipeline")

        failed = SourceWatcher(self.job, self.decryptor).run_once()

        self.assertEqual(failed, 0)
        self.assertEqual(
            sorted(path.name for path in self.job.output_dir.iterdir()), ["SBI_RESPONSE_0001.txt", "SBI_RESPONSE_0002"]
        )
        self.assertEqual(
            sorted(path.name for path in self.job.source_dir.iterdir() if path.is_file()),
            ["._SBI_RESPONSE_0003.txt.pgp", "readme.txt"],
        )

    def test_our_new_key_never_expires(self):
        gpg = open_test_keyring(self.tmp / "new", self.addCleanup)
        fingerprint = create_key_pair(gpg, "Ours", "ours@example.invalid", PASSPHRASE, key_length=2048, expires="0")

        self.assertIsNone(key_expiry(gpg.list_keys(keys=[fingerprint])[0]))
        Decryptor(gpg, PASSPHRASE).check_keys()


class KeyStatusTest(unittest.TestCase):
    """Key entries as gpg.list_keys() returns them: "trust" is gpg's validity, "cap" what the key can do."""

    def key(self, trust="-", cap="scESC", expires="", subkeys=()):
        return {"trust": trust, "cap": cap, "expires": expires, "subkey_info": dict(enumerate(subkeys))}

    def test_usable_and_unusable_keys(self):
        self.assertIsNone(key_problem(self.key()))
        self.assertEqual(key_problem(self.key(trust="e", cap="sc")), "has expired")
        self.assertEqual(key_problem(self.key(trust="r")), "has been revoked")
        self.assertIn("can't be used for encryption", key_problem(self.key(cap="scSC")))

    def test_expiry_is_the_soonest_of_the_key_and_its_encryption_subkeys(self):
        self.assertIsNone(key_expiry(self.key()))
        key = self.key(
            expires="1795092464",
            subkeys=[
                {"cap": "e", "trust": "-", "expires": "1790000000"},
                {"cap": "e", "trust": "e", "expires": "1700000000"},  # already expired: ignored
                {"cap": "s", "trust": "-", "expires": "1600000000"},  # signing only: ignored
            ],
        )
        self.assertEqual(key_expiry(key).timestamp(), 1790000000)


class SettingsTest(unittest.TestCase):
    def environment(self, **settings):
        return mock.patch.dict(os.environ, settings, clear=True)

    def load(self, **settings) -> EncryptionSettings:
        with self.environment(**settings), mock.patch("pipeline.config.load_dotenv"):
            return load_encryption_settings()

    def load_decryption(self, **settings) -> DecryptionSettings:
        with self.environment(**settings), mock.patch("pipeline.config.load_dotenv"):
            return load_decryption_settings()

    def test_defaults(self):
        settings = self.load()

        self.assertEqual(settings.job.source_dir, PROJECT_DIR / "Source")
        self.assertEqual(settings.job.output_dir, PROJECT_DIR / "Sink")
        self.assertEqual(settings.job.archive_dir, PROJECT_DIR / "Source" / "archive")
        self.assertEqual(settings.job.file_patterns, ("SBI_*.txt",))
        self.assertEqual(settings.recipients, ())
        # What SBI asked for: AES256, no compression, ASCII-armored, no signature.
        self.assertEqual((settings.cipher, settings.compression, settings.armor), ("AES256", "none", True))
        self.assertIsNone(settings.signing_key)

    def test_decryption_defaults(self):
        settings = self.load_decryption()

        self.assertEqual(settings.job.source_dir, PROJECT_DIR / "Inbound")
        self.assertEqual(settings.job.output_dir, PROJECT_DIR / "Decrypted")
        self.assertEqual(settings.job.archive_dir, PROJECT_DIR / "Inbound" / "archive")
        self.assertEqual(settings.job.file_patterns, ("*.pgp", "*.gpg", "*.asc"))
        self.assertEqual(settings.gnupg_home, PROJECT_DIR / "gnupg_home_decrypt")
        self.assertIsNone(settings.passphrase)

    def test_the_passphrase_is_kept_exactly_as_written(self):
        settings = self.load_decryption(DECRYPT_KEY_PASSPHRASE=" five random words, spaces kept ")

        self.assertEqual(settings.passphrase, " five random words, spaces kept ")

    def test_the_env_file_is_read_literally(self):
        folder = temporary_folder(self)
        (folder / ".env").write_text("DECRYPT_KEY_PASSPHRASE=pa${HOME}ss word\n")

        with self.environment(), mock.patch("pipeline.config.PROJECT_DIR", folder):
            self.assertEqual(load_decryption_settings().passphrase, "pa${HOME}ss word")

    def test_how_to_write_a_passphrase_in_the_env_file(self):
        self.assertEqual(how_to_write_in_env_file("correct horse battery staple"), "as is")
        self.assertEqual(how_to_write_in_env_file("pass #word"), "in single quotes")  # " #" starts a comment
        self.assertEqual(how_to_write_in_env_file(" spaces at the ends "), "in single quotes")
        self.assertIsNone(how_to_write_in_env_file("it's #both"))

    def test_several_file_patterns(self):
        settings = self.load(FILE_PATTERN="SBI_*.txt, SBI_*.csv")

        self.assertEqual(settings.job.file_patterns, ("SBI_*.txt", "SBI_*.csv"))

    def test_format_settings(self):
        settings = self.load(CIPHER_ALGO="aes128", COMPRESSION="ZLIB", ARMOR="false")

        self.assertEqual((settings.cipher, settings.compression, settings.armor), ("AES128", "zlib", False))
        with self.assertRaises(ConfigError):
            self.load(CIPHER_ALGO="3DES")
        with self.assertRaises(ConfigError):
            self.load(COMPRESSION="gzip")

    def test_fingerprints_are_normalised(self):
        settings = self.load(RECIPIENT_FINGERPRINTS="abcd 1234 abcd 1234 abcd 1234 abcd 1234 abcd 1234, " + "F" * 40)

        self.assertEqual(settings.recipients, ("ABCD1234" * 5, "F" * 40))

    def test_short_key_ids_are_refused(self):
        with self.assertRaises(ConfigError):
            self.load(RECIPIENT_FINGERPRINTS="ABCD1234")

    def test_folders_must_differ(self):
        with self.assertRaises(ConfigError):
            self.load(SOURCE_DIR="data", SINK_DIR="data")
        with self.assertRaises(ConfigError):
            self.load_decryption(DECRYPT_SOURCE_DIR="data", DECRYPT_DESTINATION_DIR="data")

    def test_the_two_pipelines_must_not_share_folders(self):
        # Decrypted files landing in Source would be encrypted and sent back to SBI.
        for load in (self.load, self.load_decryption):
            with self.subTest(load.__name__), self.assertRaises(ConfigError):
                load(DECRYPT_DESTINATION_DIR="Source")

    def test_the_two_pipelines_must_not_share_a_keyring(self):
        for load in (self.load, self.load_decryption):
            with self.subTest(load.__name__), self.assertRaises(ConfigError):
                load(DECRYPT_GNUPG_HOME="gnupg_home")

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
