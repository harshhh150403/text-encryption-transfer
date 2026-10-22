"""Create OUR key pair for the decryption pipeline, directly in its keyring.

Run this on the server where the decryption pipeline runs, so the private key never travels:

    python scripts/create_decryption_key.py --name "<your company> - SBI file exchange" --email <our contact email>

It asks for a passphrase, creates the key (RSA 4096, never expires) in DECRYPT_GNUPG_HOME, and
writes three files into key_export/:

    our_public_key.asc          send to SBI: they encrypt the files they send us with it
    PRIVATE_KEY_BACKUP.asc      for IT's secure vault, protected by the passphrase
    revocation_certificate.asc  for the vault too: cancels the key if it is ever compromised

Then set DECRYPT_KEY_PASSPHRASE in .env, and delete key_export/ once the files are with SBI and IT.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import PROJECT_DIR, ConfigError, how_to_write_in_env_file, load_decryption_settings
from pipeline.gpg import PgpError, ask_new_passphrase, create_key_pair, describe_key, grouped_fingerprint, open_keyring


def main() -> int:
    parser = argparse.ArgumentParser(description="Create our key pair for decrypting the files SBI sends us.")
    parser.add_argument("--name", required=True, help='what the key is for, e.g. "<company> - SBI file exchange"')
    parser.add_argument("--email", required=True, help="our contact email address, shown to SBI with the key")
    parser.add_argument("--output", type=Path, default=PROJECT_DIR / "key_export", help="folder for the files")
    args = parser.parse_args()

    if args.output.exists() and any(args.output.iterdir()):
        print(f"{args.output} is not empty. Hand over or delete the files from the last run first.", file=sys.stderr)
        return 1
    try:
        settings = load_decryption_settings()
        gpg = open_keyring(settings.gnupg_home, settings.gpg_binary)
        existing = gpg.list_keys(secret=True)
    except (ConfigError, PgpError) as exc:
        print(exc, file=sys.stderr)
        return 1
    if existing:
        print(f"The decryption keyring ({settings.gnupg_home}) already holds our private key:", file=sys.stderr)
        for key in existing:
            print(f"  {describe_key(key)}", file=sys.stderr)
        print("Nothing was changed. Don't replace it lightly: files SBI encrypts for it can only be", file=sys.stderr)
        print("decrypted with it.", file=sys.stderr)
        return 1

    while True:
        passphrase = ask_new_passphrase()
        env_form = how_to_write_in_env_file(passphrase)  # the pipeline reads it from .env
        if env_form:
            break
        print("This passphrase can't be stored in .env: it starts with a quote, or it contains a single")
        print("quote (') together with a #, or a space at the start or end. Choose another.")
    try:
        print("Creating the key pair (RSA 4096, never expires). This can take a minute...")
        fingerprint = create_key_pair(gpg, args.name, args.email, passphrase, key_length=4096, expires="0")
        public_key = gpg.export_keys(fingerprint)
        private_key = gpg.export_keys(fingerprint, secret=True, passphrase=passphrase)
        if not (public_key and private_key):
            raise PgpError("GnuPG could not export the new key")
        revocation = (settings.gnupg_home / "openpgp-revocs.d" / f"{fingerprint}.rev").read_text(encoding="utf-8")

        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "our_public_key.asc").write_text(public_key, encoding="utf-8")
        (args.output / "revocation_certificate.asc").write_text(revocation, encoding="utf-8")
        backup_file = args.output / "PRIVATE_KEY_BACKUP.asc"
        backup_file.write_text(private_key, encoding="utf-8")
        if os.name != "nt":
            backup_file.chmod(0o600)
    except (PgpError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print(f"\nFingerprint: {grouped_fingerprint(fingerprint)}")
    print(f"Our private key is in {settings.gnupg_home}")
    print(f"Files written to {args.output}:")
    print("  our_public_key.asc          send to SBI")
    print("  PRIVATE_KEY_BACKUP.asc      for IT's secure vault (protected by the passphrase)")
    print("  revocation_certificate.asc  for IT's secure vault")
    print("\nNext:")
    if env_form == "as is":
        print("  1. Put the passphrase in .env, exactly as you typed it:  DECRYPT_KEY_PASSPHRASE=<the passphrase>")
    else:
        print("  1. Put the passphrase in .env IN SINGLE QUOTES:  DECRYPT_KEY_PASSPHRASE='<the passphrase>'")
        print("     (it contains a # or a space at the start or end, which .env would otherwise change)")
    print("  2. Check it:  python main.py decrypt --once")
    print("  3. Send our_public_key.asc to SBI, and confirm the fingerprint above with them by phone.")
    print("  4. Give PRIVATE_KEY_BACKUP.asc and revocation_certificate.asc to IT for the vault, and store")
    print("     the passphrase separately (for example in IT's password manager).")
    print(f"  5. Delete {args.output} from this computer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
