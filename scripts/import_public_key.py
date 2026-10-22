"""Import a recipient's public key (for example SBI's) into the pipeline's keyring.

    python scripts/import_public_key.py path/to/sbi_public_key.asc

The file may hold several keys; each is listed with whether it can be used. Before using a key,
confirm its fingerprint with the recipient over a separate channel, such as a phone call, then put
the fingerprint in RECIPIENT_FINGERPRINTS in .env.
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import ConfigError, load_encryption_settings
from pipeline.encryptor import EXPIRY_WARNING_DAYS, uses_gnupg_only_format
from pipeline.gpg import PgpError, import_public_key, key_expiry, key_problem, open_keyring


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a recipient's public key into the pipeline's keyring.")
    parser.add_argument("key_file", type=Path, help="the public key file (.asc, .gpg, .pgp or .txt)")
    args = parser.parse_args()

    try:
        settings = load_encryption_settings()
        gpg = open_keyring(settings.gnupg_home, settings.gpg_binary)
        keys = gpg.list_keys(keys=import_public_key(gpg, args.key_file))
        print(f"Imported {len(keys)} key{'s' if len(keys) != 1 else ''} from {args.key_file.name}:")
        usable, ocb = [], False
        for number, key in enumerate(keys, 1):
            print(f"\n  {number}. {', '.join(key['uids']) or '(no name)'}")
            print(f"     fingerprint: {key['fingerprint']}")
            problem = key_problem(key)
            if problem:
                print(f"     NOT USABLE:  this key {problem}")
                continue
            usable.append(key["fingerprint"])
            print(f"     expires:     {_expiry(key)}")
            if uses_gnupg_only_format(gpg, [key["fingerprint"]], settings.cipher):
                print("     format:      GnuPG's OCB format (see the note below)")
                ocb = True
    except (ConfigError, PgpError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print()
    if not usable:
        print("None of these keys can be used for encryption. Ask the recipient for a valid key.")
        return 1
    if len(usable) == 1:
        print("Confirm the fingerprint with the recipient (for example by phone), then set this in .env:")
        print(f"RECIPIENT_FINGERPRINTS={usable[0]}")
    else:
        print(f"{len(usable)} of these keys can be used, but files should be encrypted for only one of them.")
        print("Ask the recipient which one, and confirm its fingerprint with them (for example by phone).")
        print("Then set it in .env:")
        print("RECIPIENT_FINGERPRINTS=<the fingerprint the recipient confirms>")
    if ocb:
        print("\nNOTE: a key marked OCB asks gpg to encrypt in GnuPG's newer OCB format. GnuPG 2.3+ and")
        print("Kleopatra can decrypt it, but many other PGP programs can't, so the pipeline refuses such a key")
        print("unless ALLOW_GNUPG_ONLY_FORMAT=true is set in .env. Set that only if the recipient confirms")
        print("their software decrypts OCB. Otherwise ask them to remove OCB from the key's preferences and")
        print("send it again (see README).")
    return 0


def _expiry(key: dict) -> str:
    expires = key_expiry(key)
    if expires is None:
        return "never"
    days_left = (expires - datetime.now(timezone.utc)).days
    text = f"{expires.date()} (in {days_left} days)"
    if days_left <= EXPIRY_WARNING_DAYS:
        text += " - SOON: ask the recipient for its replacement"
    return text


if __name__ == "__main__":
    sys.exit(main())
