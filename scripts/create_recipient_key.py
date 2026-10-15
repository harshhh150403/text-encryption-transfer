"""Create a key pair for a recipient such as SBI, and export the files to hand over.

Run this on a trusted computer, not on the pipeline server:

    python scripts/create_recipient_key.py --name "SBI - <your company> file exchange" --email <SBI contact>

It asks for a passphrase, then writes three files into key_handover/:

    public_key.asc              keep: import it into the pipeline with scripts/import_public_key.py
    PRIVATE_KEY.asc             for the recipient only; protected by the passphrase
    revocation_certificate.asc  for the recipient: lets them cancel the key if it ever leaks

The key is created in a temporary keyring that is deleted straight afterwards, so the only copy of
the private key is the file in key_handover/. Hand the files over, then delete that folder.

Use this rather than Kleopatra's "New Key Pair": keys made there would make gpg encrypt files in a
format that most PGP programs other than GnuPG can't decrypt (see COMPATIBLE_PREFERENCES).
"""

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import PROJECT_DIR, ConfigError, load_settings
from pipeline.encryptor import EncryptionError, create_key_pair, open_keyring

MIN_PASSPHRASE_LENGTH = 12


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a key pair for a recipient and export it for handover.")
    parser.add_argument("--name", required=True, help='what the key is for, e.g. "SBI - <company> file exchange"')
    parser.add_argument("--email", required=True, help="the recipient's contact email address")
    parser.add_argument("--expires", default="2y", help="how long the key is valid, e.g. 1y or 2y (default 2y)")
    parser.add_argument("--output", type=Path, default=PROJECT_DIR / "key_handover", help="folder for the files")
    args = parser.parse_args()

    if args.output.exists() and any(args.output.iterdir()):
        print(f"{args.output} is not empty. Hand over or delete the files from the last run first.", file=sys.stderr)
        return 1
    passphrase = _ask_passphrase()

    keyring = Path(tempfile.mkdtemp())
    try:
        settings = load_settings()
        gpg = open_keyring(keyring / "k", settings.gpg_binary)
        print("Creating the key pair (RSA 4096). This can take a minute...")
        fingerprint = create_key_pair(gpg, args.name, args.email, passphrase, key_length=4096, expires=args.expires)
        public_key = gpg.export_keys(fingerprint)
        private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
        revocation = (keyring / "k" / "openpgp-revocs.d" / f"{fingerprint}.rev").read_text(encoding="utf-8")
        if not (public_key and private_key):
            raise EncryptionError("GnuPG could not export the new key")

        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "public_key.asc").write_text(public_key, encoding="utf-8")
        (args.output / "revocation_certificate.asc").write_text(revocation, encoding="utf-8")
        private_key_file = args.output / "PRIVATE_KEY.asc"
        private_key_file.write_text(private_key, encoding="utf-8")
        if os.name != "nt":
            private_key_file.chmod(0o600)
    except (ConfigError, EncryptionError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    finally:
        if shutil.which("gpgconf"):  # stop the temporary keyring's background agent before deleting it
            subprocess.run(["gpgconf", "--homedir", str(keyring / "k"), "--kill", "gpg-agent"], capture_output=True)
        shutil.rmtree(keyring, ignore_errors=True)

    grouped = " ".join(fingerprint[i : i + 4] for i in range(0, len(fingerprint), 4))
    print(f"\nFingerprint: {grouped}")
    print(f"Files written to {args.output}:")
    print("  public_key.asc              keep: python scripts/import_public_key.py <this file>")
    print("  PRIVATE_KEY.asc             for the recipient only")
    print("  revocation_certificate.asc  for the recipient")
    print("\nNext:")
    print("  1. Send PRIVATE_KEY.asc and revocation_certificate.asc through one channel,")
    print("     and the passphrase through a different one (for example a phone call).")
    print("  2. Ask the recipient to read the fingerprint back to you after importing the key.")
    print("  3. Import public_key.asc into the pipeline, then delete this folder.")
    return 0


def _ask_passphrase() -> str:
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


if __name__ == "__main__":
    sys.exit(main())
