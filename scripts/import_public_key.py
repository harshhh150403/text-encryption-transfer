"""Import a recipient's public key (for example SBI's) into the pipeline's keyring.

    python scripts/import_public_key.py path/to/sbi_public_key.asc

Before using the key, confirm its fingerprint with the recipient over a separate channel, such as a
phone call, then put the fingerprint in RECIPIENT_FINGERPRINTS in .env.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import ConfigError, load_settings
from pipeline.encryptor import EncryptionError, import_public_key, open_keyring, uses_gnupg_only_format


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a recipient's public key into the pipeline's keyring.")
    parser.add_argument("key_file", type=Path, help="the public key file (.asc, .gpg or .pgp)")
    args = parser.parse_args()

    try:
        settings = load_settings()
        gpg = open_keyring(settings.gnupg_home, settings.gpg_binary)
        fingerprints = import_public_key(gpg, args.key_file)
    except (ConfigError, EncryptionError) as exc:
        print(exc, file=sys.stderr)
        return 1

    for key in gpg.list_keys(keys=fingerprints):
        expires = datetime.fromtimestamp(int(key["expires"])).date() if key["expires"] else "never"
        print(f"Imported: {', '.join(key['uids'])}")
        print(f"  fingerprint: {key['fingerprint']}")
        print(f"  expires:     {expires}")
    if uses_gnupg_only_format(gpg, fingerprints):
        print("\nWARNING: files encrypted for this key would use GnuPG's newer OCB format, which most PGP")
        print("programs other than GnuPG can't decrypt. The pipeline will refuse to start with it unless")
        print("ALLOW_GNUPG_ONLY_FORMAT=true is set in .env, which is only safe if the recipient confirms")
        print("they decrypt with GnuPG 2.3 or newer. Otherwise create the key with scripts/create_recipient_key.py.")
    print("\nConfirm the fingerprint with the recipient (for example by phone), then set this in .env:")
    print(f"RECIPIENT_FINGERPRINTS={','.join(fingerprints)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
