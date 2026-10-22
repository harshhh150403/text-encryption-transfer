"""PGP encryption of files we send to SBI, with SBI's public key."""

import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

import gnupg

from .gpg import PgpError, describe_key, gpg_messages, key_expiry, key_problem

log = logging.getLogger(__name__)

ENCRYPTED_SUFFIX = ".pgp"

# Warn this many days before a key expires, so a new key can be arranged in time.
EXPIRY_WARNING_DAYS = 30

# OpenPGP packet types that can hold the encrypted data of a file.
CLASSIC_DATA_PACKET = 18  # CFB+MDC: every PGP program can decrypt it
OCB_DATA_PACKET = 20  # GnuPG's OCB format: only GnuPG 2.3+ and a few others can decrypt it


def uses_gnupg_only_format(gpg: gnupg.GPG, recipients: Iterable[str], cipher: str = "AES256") -> bool:
    """True if files encrypted for these recipients would use GnuPG's OCB format (see COMPATIBLE_PREFERENCES).

    gpg chooses OCB whenever every recipient's key says it supports OCB, whatever options it is given.
    """
    result = gpg.encrypt(
        b"format check", list(recipients), always_trust=True, armor=False, extra_args=["--cipher-algo", cipher]
    )
    if not result.ok:
        raise PgpError(f"GnuPG could not encrypt a test message: {result.status} ({gpg_messages(result.stderr)})")
    return data_packet_type(result.data) == OCB_DATA_PACKET


class Encryptor:
    """Encrypts files for a fixed list of recipients, optionally signing them with our own key.

    The file format defaults to what SBI asked for: AES256, no compression, ASCII-armored.
    """

    action = "Encrypted"  # for the log: "Encrypted <file> to ..."

    def __init__(
        self,
        gpg: gnupg.GPG,
        recipients: Iterable[str],
        signing_key: str | None = None,
        signing_passphrase: str | None = None,
        *,
        cipher: str = "AES256",
        compression: str = "none",
        armor: bool = True,
        allow_gnupg_only_format: bool = False,
    ):
        self._gpg = gpg
        self._recipients = list(recipients)
        self._signing_key = signing_key
        self._signing_passphrase = signing_passphrase
        self._cipher = cipher
        self._compression = compression
        self._armor = armor
        self._allow_gnupg_only_format = allow_gnupg_only_format

    def check_keys(self) -> None:
        """Stop before any file is touched if a key is missing or unusable; warn about keys near expiry."""
        if not self._recipients:
            raise PgpError(
                "No recipient key is configured. Set RECIPIENT_FINGERPRINTS in .env "
                "(to try the pipeline with a test key, run: python scripts/setup_test_keys.py)."
            )
        public_keys = {key["fingerprint"]: key for key in self._gpg.list_keys()}
        for fingerprint in self._recipients:
            if fingerprint not in public_keys:
                raise PgpError(
                    f"Recipient key {fingerprint} is not in the pipeline's keyring. "
                    "Import it with: python scripts/import_public_key.py <public key file>"
                )
            _check_key(public_keys[fingerprint], "e", "encryption")
            log.info("Encrypting for %s", describe_key(public_keys[fingerprint]))
        if self._signing_key:
            if self._signing_key not in {key["fingerprint"] for key in self._gpg.list_keys(secret=True)}:
                raise PgpError(f"The private key for signing ({self._signing_key}) is not in the pipeline's keyring")
            _check_key(public_keys[self._signing_key], "s", "signing")
            log.info("Signing with %s", describe_key(public_keys[self._signing_key]))
        ocb = uses_gnupg_only_format(self._gpg, self._recipients, self._cipher)
        if ocb and not self._allow_gnupg_only_format:
            raise PgpError(
                "The recipient's key asks for GnuPG's newer OCB format, so gpg would encrypt files in it. "
                "GnuPG 2.3+ and Kleopatra can decrypt OCB, but many other PGP programs can't. Keys created "
                "by recent GnuPG or Kleopatra versions do this. Either ask the recipient to confirm that "
                "their software decrypts OCB and then set ALLOW_GNUPG_ONLY_FORMAT=true in .env, or ask them "
                "to remove OCB from their key's preferences and send the public key again (see README)."
            )
        log.info(
            "Files are %s, encrypted with %s%s, %s and %s",
            "ASCII-armored" if self._armor else "binary",
            self._cipher,
            " in GnuPG's OCB mode" if ocb else "",
            "not compressed" if self._compression == "none" else f"compressed with {self._compression.upper()}",
            "signed" if self._signing_key else "not signed",
        )

    def output_name(self, source_name: str) -> str:
        """The encrypted file's name: the original name with .pgp added."""
        return source_name + ENCRYPTED_SUFFIX

    def encrypt_file(self, source: Path, output: Path) -> None:
        """Encrypt source into output in the configured format."""
        result = self._gpg.encrypt_file(
            str(source),
            self._recipients,
            # This keyring only holds keys imported on purpose, and recipients are given by full
            # fingerprint, so gpg's web-of-trust check (which rejects keys nobody has certified) adds nothing.
            always_trust=True,
            armor=self._armor,
            output=str(output),
            sign=self._signing_key,
            passphrase=self._signing_passphrase,
            extra_args=[
                # Keep the original file name inside the encrypted file, for recipients whose tools use it.
                "--set-filename", source.name,
                "--cipher-algo", self._cipher,
                "--compress-algo", self._compression,
            ],
        )
        if not result.ok:
            raise PgpError(f"GnuPG could not encrypt {source.name}: {result.status} ({gpg_messages(result.stderr)})")

    convert = encrypt_file  # what the pipeline calls for each file


def _check_key(key: dict, capability: str, purpose: str) -> None:
    """Raise if the key can't be used for purpose; warn if it expires within EXPIRY_WARNING_DAYS."""
    problem = key_problem(key, capability, purpose)
    if problem:
        raise PgpError(f"Key {describe_key(key)} {problem}")
    expires = key_expiry(key, capability)
    if expires is not None:
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left <= EXPIRY_WARNING_DAYS:
            log.warning(
                "Key %s expires on %s (in %d days). Arrange a new key before then, or encryption will stop.",
                describe_key(key), expires.date(), days_left,
            )


def data_packet_type(message: bytes) -> int:
    """The type of packet holding the encrypted data in a binary OpenPGP message.

    The packets before it (one per recipient) are skipped by reading their headers (RFC 4880, 4.2).
    """
    position = 0
    while position < len(message):
        header = message[position]
        if header & 0x40:  # new-format header: the type, then a length of 1, 2 or 5 bytes
            packet_type = header & 0x3F
            first = message[position + 1]
            if first < 192:
                header_size, length = 2, first
            elif first < 224:
                header_size, length = 3, ((first - 192) << 8) + message[position + 2] + 192
            else:  # 255: four more length bytes (data packets may use other values, but end the loop)
                header_size, length = 6, int.from_bytes(message[position + 2 : position + 6], "big")
        else:  # old-format header: the type and the size of the length field share the first byte
            packet_type = (header >> 2) & 0x0F
            header_size = 1 + (1, 2, 4, 0)[header & 0x03]
            length = int.from_bytes(message[position + 1 : position + header_size], "big")
        if packet_type in (CLASSIC_DATA_PACKET, OCB_DATA_PACKET):
            return packet_type
        position += header_size + length
    raise PgpError("Could not find the encrypted data in GnuPG's output")
