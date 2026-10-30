"""PGP decryption of files SBI sends us, with our own private key."""

import logging
import os
import re
from pathlib import Path

import gnupg

from .gpg import PgpError, describe_key, gpg_messages, key_problem, stop_gpg_agent

log = logging.getLogger(__name__)

# Extensions an encrypted file may have. The decrypted file gets the same name without it.
ENCRYPTED_EXTENSIONS = (".pgp", ".gpg", ".asc")


def decrypted_file_name(encrypted_name: str) -> str:
    """The decrypted file's name: the encrypted file's name without .pgp, .gpg or .asc.

    SBI-style names with .txt at the end are understood both ways: SBI_X.pgp.txt and SBI_X.txt.pgp.txt
    both become SBI_X.txt.
    """
    stem, extension = os.path.splitext(encrypted_name)
    if extension.lower() == ".txt" and os.path.splitext(stem)[1].lower() in ENCRYPTED_EXTENSIONS:
        stem = os.path.splitext(stem)[0]  # SBI_X, or SBI_X.txt
        return stem if os.path.splitext(stem)[1] else stem + ".txt"
    return stem if stem and extension.lower() in ENCRYPTED_EXTENSIONS else encrypted_name

# libgpg-error's code for a wrong passphrase. gpg reports errors in status lines such as
# "[GNUPG:] ERROR pkdecrypt_failed 67108875": the low 16 bits are the code (11), the rest says which
# part of GnuPG reported it. Unlike gpg's messages, these lines are never translated.
BAD_PASSPHRASE_CODE = 11


class Decryptor:
    """Decrypts files that were encrypted for our key, using our private key and its passphrase."""

    action = "Decrypted"  # for the log: "Decrypted <file> to ..."

    def __init__(self, gpg: gnupg.GPG, passphrase: str | None = None):
        if passphrase is not None and not gpg.is_valid_passphrase(passphrase):
            raise PgpError("DECRYPT_KEY_PASSPHRASE must not contain line breaks")
        self._gpg = gpg
        self._passphrase = passphrase
        # With a passphrase, python-gnupg tells gpg to take it from the pipeline instead of asking for
        # it. Without one, say the same, so that gpg fails straight away instead of opening a
        # passphrase prompt that nobody would answer when the pipeline runs in the background.
        self._extra_args = None if passphrase else ["--pinentry-mode", "loopback"]

    def check_keys(self) -> None:
        """Stop before any file is touched unless our private key is there and the passphrase unlocks it."""
        # gpg-agent, which unlocks the key, remembers a passphrase for a while after it was used. Stop it
        # first, so the check below tests the configured passphrase and not one it still remembers.
        stop_gpg_agent(Path(self._gpg.gnupghome), self._gpg.gpgbinary)
        usable = 0
        for key in self._gpg.list_keys(secret=True):
            problem = key_problem(key, "e", "decryption")
            if problem:
                log.warning("Private key %s %s", describe_key(key), problem)
                continue
            self._check_passphrase(key)
            log.info("Decrypting with %s", describe_key(key))
            usable += 1
        if not usable:
            raise PgpError(
                "There is no usable private key in the decryption keyring. Create ours with: "
                'python scripts/create_decryption_key.py --name "<company> - SBI file exchange" --email <email>'
            )

    def output_name(self, source_name: str) -> str:
        """The decrypted file's name (see decrypted_file_name)."""
        return decrypted_file_name(source_name)

    def decrypt_file(self, source: Path, output: Path) -> None:
        """Decrypt source into output. Anything gpg wrote to output before failing is left to the caller."""
        result = self._gpg.decrypt_file(
            str(source), passphrase=self._passphrase, output=str(output), extra_args=self._extra_args
        )
        if not result.ok:
            raise PgpError(f"GnuPG could not decrypt {source.name}: {_problem(result)}")
        if result.key_id is None:  # gpg reports the key a file is encrypted for; a password has none
            raise PgpError(f"{source.name} was encrypted with a password, not with our public key")

    convert = decrypt_file  # what the pipeline calls for each file

    def _check_passphrase(self, key: dict) -> None:
        """Encrypt a test message for the key and decrypt it again, which needs the passphrase."""
        probe = self._gpg.encrypt(b"passphrase check", key["fingerprint"], always_trust=True, armor=False)
        if not probe.ok:
            raise PgpError(f"GnuPG could not encrypt a test message for {describe_key(key)}: {gpg_messages(probe.stderr)}")
        result = self._gpg.decrypt(probe.data, passphrase=self._passphrase, extra_args=self._extra_args)
        if not result.ok:
            raise PgpError(f"Could not unlock private key {describe_key(key)}: {_problem(result)}")


def _problem(result) -> str:
    """Why decryption failed, from gpg's status lines (in result.stderr) and messages."""
    status_lines, details = result.stderr, gpg_messages(result.stderr)
    if "NEED_PASSPHRASE_SYM" in status_lines:
        return "it was encrypted with a password, not with our public key"
    if "BAD_PASSPHRASE" in status_lines or BAD_PASSPHRASE_CODE in _error_codes(status_lines):
        return "the passphrase is wrong (check DECRYPT_KEY_PASSPHRASE in .env)"
    if result.status == "need passphrase":
        return "our private key needs its passphrase (set DECRYPT_KEY_PASSPHRASE in .env)"
    if result.status == "no secret key":
        return f"it was not encrypted for our key ({details})"
    if "ENC_TO" not in status_lines and "BEGIN_DECRYPTION" not in status_lines:
        return f"it is not a PGP-encrypted file, or it is damaged ({details})"
    return f"{result.status or 'decryption failed'}, the file may be damaged ({details})"


def _error_codes(status_lines: str) -> set[int]:
    """The error codes in gpg's ERROR status lines."""
    return {int(code) & 0xFFFF for code in re.findall(r"^\[GNUPG:\] ERROR \S+ (\d+)", status_lines, re.MULTILINE)}
