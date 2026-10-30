"""GnuPG keyrings and keys, shared by the encryption and decryption pipelines (through python-gnupg)."""

import getpass
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import gnupg

# Preferences for keys we create. Listing them explicitly leaves out GnuPG's newer OCB mode. Recent
# GnuPG (and Kleopatra) otherwise mark new keys as OCB-capable, and gpg then encrypts files for them
# in a format that most other PGP programs can't decrypt.
COMPATIBLE_PREFERENCES = "AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed"

MIN_PASSPHRASE_LENGTH = 12


class PgpError(Exception):
    """GnuPG is unavailable, a key is missing or unusable, or encryption or decryption failed."""


def open_keyring(gnupg_home: Path, gpg_binary: str = "gpg") -> gnupg.GPG:
    """Open the GnuPG keyring in the gnupg_home folder, creating the folder if needed."""
    if shutil.which(gpg_binary) is None:
        raise PgpError(
            f"GnuPG was not found ({gpg_binary}). Install it (Windows: Gpg4win, macOS: brew install gnupg), "
            "or set GPG_BINARY in .env to the full path of gpg."
        )
    gnupg_home.mkdir(mode=0o700, parents=True, exist_ok=True)  # private to this user, as gpg expects
    try:
        return gnupg.GPG(gnupghome=str(gnupg_home), gpgbinary=gpg_binary)
    except (OSError, ValueError) as exc:
        raise PgpError(f"GnuPG ({gpg_binary}) could not be started: {exc}") from exc


def stop_gpg_agent(gnupg_home: Path, gpg_binary: str = "gpg") -> None:
    """Stop the background gpg-agent that GnuPG runs for a keyring, if it is running.

    Needed before deleting a keyring folder (on Windows the agent keeps its files locked) and after
    changing the agent's settings (it only reads them when it starts).
    """
    gpgconf = _gpgconf(gpg_binary)
    if gpgconf is None:
        return
    try:
        subprocess.run([gpgconf, "--homedir", str(gnupg_home), "--kill", "gpg-agent"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def check_public_key_file(gpg: gnupg.GPG, key_file: Path) -> None:
    """Raise unless key_file holds public keys only.

    A private key is refused: the encryption pipeline only ever needs the recipient's public key.
    """
    if not key_file.is_file():
        raise PgpError(f"Key file not found: {key_file}")
    keys = gpg.scan_keys(str(key_file))
    if not keys:
        raise PgpError(f"No PGP key found in {key_file}")
    if any(key["type"] == "sec" for key in keys):
        raise PgpError(
            f"{key_file} contains a PRIVATE key, which must never be stored with the encryption pipeline. "
            "Export only the public key and import that instead."
        )


def import_public_key(gpg: gnupg.GPG, key_file: Path) -> list[str]:
    """Import the public key(s) in key_file (see check_public_key_file) and return their fingerprints."""
    check_public_key_file(gpg, key_file)
    result = gpg.import_keys_file(str(key_file))
    if not result.fingerprints:
        raise PgpError(f"Could not import {key_file}: {gpg_messages(result.stderr)}")
    return sorted(set(result.fingerprints))


def remove_public_keys(gpg: gnupg.GPG) -> list[dict]:
    """Remove the public keys that have no private key in this keyring, such as SBI's, and return them.

    Our own keys (a signing key, if signing is used) are kept.
    """
    ours = {key["fingerprint"] for key in gpg.list_keys(secret=True)}
    removed = [key for key in gpg.list_keys() if key["fingerprint"] not in ours]
    if removed:
        result = gpg.delete_keys([key["fingerprint"] for key in removed])
        if str(result) != "ok":
            raise PgpError(f"Could not remove the old keys: {result} ({gpg_messages(result.stderr)})")
    return removed


def create_key_pair(
    gpg: gnupg.GPG, name: str, email: str, passphrase: str | None, key_length: int = 4096, expires: str = "2y"
) -> str:
    """Create an RSA key pair that any PGP program can use, and return its fingerprint.

    expires is e.g. "2y", or "0" for a key that never expires. Without a passphrase the private key is
    unprotected, which is only acceptable for test keys.
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
        raise PgpError(f"GnuPG could not create the key: {gpg_messages(key.stderr)}")
    return key.fingerprint


def key_problem(key: dict, capability: str = "e", purpose: str = "encryption") -> str | None:
    """Why the key can't be used for purpose right now, completing "Key ... ", or None if it can.

    key is an entry from gpg.list_keys(); capability is gpg's letter for the purpose: "e" (encrypt,
    which decryption needs too) or "s" (sign).
    """
    if key["trust"] == "r":
        return "has been revoked"
    if key["trust"] == "e":
        return "has expired"
    # On the main key, gpg lists in upper case what the key as a whole can be used for right now.
    if capability.upper() not in key["cap"]:
        return f"can't be used for {purpose} (part of it may have expired or been revoked)"
    return None


def key_expiry(key: dict, capability: str = "e") -> datetime | None:
    """When the key stops working for the capability: the soonest expiry of the key and its usable subkeys."""
    dates = [key["expires"]] + [
        subkey["expires"]
        for subkey in key.get("subkey_info", {}).values()
        if capability in subkey["cap"] and subkey["trust"] not in ("e", "r")
    ]
    soonest = min((int(date) for date in dates if date), default=None)
    return None if soonest is None else datetime.fromtimestamp(soonest, timezone.utc)


def describe_key(key: dict) -> str:
    name = key["uids"][0] if key["uids"] else "(no name)"
    return f"{name} [{key['fingerprint']}]"


def grouped_fingerprint(fingerprint: str) -> str:
    """The fingerprint in groups of four, the way it is read out to the other side over the phone."""
    return " ".join(fingerprint[i : i + 4] for i in range(0, len(fingerprint), 4))


def gpg_messages(stderr: str) -> str:
    """gpg's own messages, without the machine-readable status lines python-gnupg also collects."""
    return " ".join(line.strip() for line in stderr.splitlines() if line.startswith("gpg: ")) or "no details from gpg"


def ask_new_passphrase() -> str:
    """Ask for a new passphrase in the terminal, twice, without showing it (for the key scripts)."""
    print(f"Choose a passphrase for the private key (at least {MIN_PASSPHRASE_LENGTH} characters,")
    print("for example 5-6 random words). It is not shown while you type.")
    while True:
        passphrase = getpass.getpass("Passphrase: ")
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            print(f"Too short: use at least {MIN_PASSPHRASE_LENGTH} characters.")
        elif passphrase != getpass.getpass("Repeat it: "):
            print("The two entries don't match. Try again.")
        else:
            return passphrase


def _gpgconf(gpg_binary: str) -> str | None:
    """gpgconf, GnuPG's control program: next to gpg if that was given as a path, otherwise on PATH."""
    gpg = shutil.which(gpg_binary)
    if gpg:
        beside_gpg = Path(gpg).with_name("gpgconf" + Path(gpg).suffix)  # gpg.exe -> gpgconf.exe on Windows
        if beside_gpg.exists():
            return str(beside_gpg)
    return shutil.which("gpgconf")
