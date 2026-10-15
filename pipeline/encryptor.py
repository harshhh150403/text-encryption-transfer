"""GnuPG keyring access and PGP encryption, through the python-gnupg library."""

import logging
import shutil
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

import gnupg

log = logging.getLogger(__name__)

# Warn this many days before a key expires, so a new key can be arranged in time.
EXPIRY_WARNING_DAYS = 30

# Preferences for keys we create. Listing them explicitly leaves out GnuPG's newer OCB mode. Recent
# GnuPG (and Kleopatra) otherwise mark new keys as OCB-capable, and gpg then encrypts files for them
# in a format that most other PGP programs can't decrypt.
COMPATIBLE_PREFERENCES = "AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed"

# OpenPGP packet types that can hold the encrypted data of a file.
CLASSIC_DATA_PACKET = 18  # CFB+MDC: every PGP program can decrypt it
OCB_DATA_PACKET = 20  # GnuPG's OCB format: only GnuPG 2.3+ and a few others can decrypt it


class EncryptionError(Exception):
    """GnuPG is unavailable, a key is missing or unusable, or encryption failed."""


def open_keyring(gnupg_home: Path, gpg_binary: str = "gpg") -> gnupg.GPG:
    """Open the GnuPG keyring in the gnupg_home folder, creating the folder if needed."""
    if shutil.which(gpg_binary) is None:
        raise EncryptionError(
            f"GnuPG was not found ({gpg_binary}). Install it (Windows: Gpg4win, macOS: brew install gnupg), "
            "or set GPG_BINARY in .env to the full path of gpg."
        )
    gnupg_home.mkdir(mode=0o700, parents=True, exist_ok=True)  # private to this user, as gpg expects
    try:
        return gnupg.GPG(gnupghome=str(gnupg_home), gpgbinary=gpg_binary)
    except (OSError, ValueError) as exc:
        raise EncryptionError(f"GnuPG ({gpg_binary}) could not be started: {exc}") from exc


def import_public_key(gpg: gnupg.GPG, key_file: Path) -> list[str]:
    """Import the public key(s) in key_file and return their fingerprints.

    Refuses a file that contains a private key: the pipeline only ever needs the recipient's public key.
    """
    if not key_file.is_file():
        raise EncryptionError(f"Key file not found: {key_file}")
    keys = gpg.scan_keys(str(key_file))
    if not keys:
        raise EncryptionError(f"No PGP key found in {key_file}")
    if any(key["type"] == "sec" for key in keys):
        raise EncryptionError(
            f"{key_file} contains a PRIVATE key, which must never be stored with the pipeline. "
            "Export only the public key and import that instead."
        )
    result = gpg.import_keys_file(str(key_file))
    if not result.fingerprints:
        raise EncryptionError(f"Could not import {key_file}: {_gpg_messages(result.stderr)}")
    return sorted(set(result.fingerprints))


def create_key_pair(
    gpg: gnupg.GPG, name: str, email: str, passphrase: str | None, key_length: int = 4096, expires: str = "2y"
) -> str:
    """Create an RSA key pair that any PGP program can use, and return its fingerprint.

    Without a passphrase the private key is unprotected, which is only acceptable for test keys.
    """
    protection = {"passphrase": passphrase} if passphrase else {"no_protection": True}
    key = gpg.gen_key(
        gpg.gen_key_input(
            name_real=name,
            name_email=email,
            key_type="RSA",
            key_length=key_length,
            key_usage="sign",
            subkey_type="RSA",
            subkey_length=key_length,
            subkey_usage="encrypt",
            expire_date=expires,
            preferences=COMPATIBLE_PREFERENCES,
            **protection,
        )
    )
    if not key.fingerprint:
        raise EncryptionError(f"GnuPG could not create the key: {_gpg_messages(key.stderr)}")
    return key.fingerprint


def uses_gnupg_only_format(gpg: gnupg.GPG, recipients: Iterable[str]) -> bool:
    """True if files encrypted for these recipients would use GnuPG's OCB format (see COMPATIBLE_PREFERENCES)."""
    result = gpg.encrypt(b"format check", list(recipients), always_trust=True, armor=False)
    if not result.ok:
        raise EncryptionError(f"GnuPG could not encrypt a test message: {result.status} ({_gpg_messages(result.stderr)})")
    return data_packet_type(result.data) == OCB_DATA_PACKET


class Encryptor:
    """Encrypts files for a fixed list of recipients, optionally signing them with our own key."""

    def __init__(
        self,
        gpg: gnupg.GPG,
        recipients: Iterable[str],
        signing_key: str | None = None,
        signing_passphrase: str | None = None,
        allow_gnupg_only_format: bool = False,
    ):
        self._gpg = gpg
        self._recipients = list(recipients)
        self._signing_key = signing_key
        self._signing_passphrase = signing_passphrase
        self._allow_gnupg_only_format = allow_gnupg_only_format

    def check_keys(self) -> None:
        """Stop before any file is touched if a key is missing or unusable; warn about keys near expiry."""
        if not self._recipients:
            raise EncryptionError(
                "No recipient key is configured. Set RECIPIENT_FINGERPRINTS in .env "
                "(to try the pipeline with a test key, run: python scripts/setup_test_keys.py)."
            )
        public_keys = {key["fingerprint"]: key for key in self._gpg.list_keys()}
        for fingerprint in self._recipients:
            if fingerprint not in public_keys:
                raise EncryptionError(
                    f"Recipient key {fingerprint} is not in the pipeline's keyring. "
                    "Import it with: python scripts/import_public_key.py <public key file>"
                )
            _check_key(public_keys[fingerprint], "e", "encryption")
            log.info("Encrypting for %s", _describe(public_keys[fingerprint]))
        if self._signing_key:
            if self._signing_key not in {key["fingerprint"] for key in self._gpg.list_keys(secret=True)}:
                raise EncryptionError(
                    f"The private key for signing ({self._signing_key}) is not in the pipeline's keyring"
                )
            _check_key(public_keys[self._signing_key], "s", "signing")
            log.info("Signing with %s", _describe(public_keys[self._signing_key]))
        if not self._allow_gnupg_only_format and uses_gnupg_only_format(self._gpg, self._recipients):
            raise EncryptionError(
                "Files encrypted for the recipient key would use GnuPG's newer OCB format, which most PGP "
                "programs other than GnuPG can't decrypt. Keys created by recent GnuPG or Kleopatra versions "
                "cause this. Recreate the key with scripts/create_recipient_key.py, or, if the recipient "
                "confirms they decrypt with GnuPG 2.3 or newer, set ALLOW_GNUPG_ONLY_FORMAT=true in .env."
            )

    def encrypt_file(self, source: Path, output: Path) -> None:
        """Encrypt source into output as binary OpenPGP data."""
        result = self._gpg.encrypt_file(
            str(source),
            self._recipients,
            # This keyring only holds keys imported on purpose, and recipients are given by full
            # fingerprint, so gpg's web-of-trust check (which rejects keys nobody has certified) adds nothing.
            always_trust=True,
            armor=False,
            output=str(output),
            sign=self._signing_key,
            passphrase=self._signing_passphrase,
            # Keep the original file name inside the encrypted file, for recipients whose tools use it.
            extra_args=["--set-filename", source.name],
        )
        if not result.ok:
            raise EncryptionError(
                f"GnuPG could not encrypt {source.name}: {result.status} ({_gpg_messages(result.stderr)})"
            )


def _check_key(key: dict, capability: str, purpose: str) -> None:
    """Raise if the key can't be used for purpose; warn if it expires within EXPIRY_WARNING_DAYS.

    capability is gpg's letter for the purpose: "e" (encrypt) or "s" (sign).
    """
    if key["trust"] == "r":
        raise EncryptionError(f"Key {_describe(key)} has been revoked")
    if key["trust"] == "e":
        raise EncryptionError(f"Key {_describe(key)} has expired")
    # On the main key, gpg lists in upper case what the key as a whole can be used for right now.
    if capability.upper() not in key["cap"]:
        raise EncryptionError(
            f"Key {_describe(key)} can't be used for {purpose} (part of it may have expired or been revoked)"
        )
    expiry_dates = [key["expires"]] + [
        subkey["expires"]
        for subkey in key.get("subkey_info", {}).values()
        if capability in subkey["cap"] and subkey["trust"] not in ("e", "r")
    ]
    soonest = min((int(date) for date in expiry_dates if date), default=None)
    if soonest is not None:
        expires = datetime.fromtimestamp(soonest, timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left <= EXPIRY_WARNING_DAYS:
            log.warning(
                "Key %s expires on %s (in %d days). Arrange a new key before then, or encryption will stop.",
                _describe(key), expires.date(), days_left,
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
    raise EncryptionError("Could not find the encrypted data in GnuPG's output")


def _describe(key: dict) -> str:
    name = key["uids"][0] if key["uids"] else "(no name)"
    return f"{name} [{key['fingerprint']}]"


def _gpg_messages(stderr: str) -> str:
    """gpg's own messages, without the machine-readable status lines python-gnupg also collects."""
    return " ".join(line.strip() for line in stderr.splitlines() if line.startswith("gpg: ")) or "no details from gpg"
