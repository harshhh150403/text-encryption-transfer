"""Decrypt a file from Sink with the TEST key, to check the pipeline end to end. TEST ONLY.

This does what SBI will do with its own private key. The decrypted copy goes to test_keys/decrypted/
and is compared with the original in the archive.

    python scripts/decrypt_file.py Sink/SBI_SBIN55_20261014_0002.txt.pgp
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import ConfigError, load_settings
from pipeline.encryptor import EncryptionError, open_keyring
from scripts.setup_test_keys import RECIPIENT_KEYRING, TEST_KEYS_DIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt a .pgp file from Sink with the test key.")
    parser.add_argument("encrypted_file", type=Path)
    args = parser.parse_args()

    if not args.encrypted_file.is_file():
        print(f"File not found: {args.encrypted_file}", file=sys.stderr)
        return 1
    if not RECIPIENT_KEYRING.is_dir():
        print("No test key yet. Run: python scripts/setup_test_keys.py", file=sys.stderr)
        return 1
    try:
        settings = load_settings()
        gpg = open_keyring(RECIPIENT_KEYRING, settings.gpg_binary)
    except (ConfigError, EncryptionError) as exc:
        print(exc, file=sys.stderr)
        return 1

    original_name = args.encrypted_file.name.removesuffix(".pgp")
    output = TEST_KEYS_DIR / "decrypted" / original_name
    output.parent.mkdir(parents=True, exist_ok=True)
    result = gpg.decrypt_file(str(args.encrypted_file), output=str(output))
    if not result.ok:
        print(f"Could not decrypt {args.encrypted_file.name}: {result.status}", file=sys.stderr)
        return 1
    print(f"Decrypted to {output}")
    if result.valid:
        print(f"Signed by {result.username}: the signature is valid")

    archived = settings.archive_dir / original_name
    if not archived.is_file():
        return 0
    if output.read_bytes() == archived.read_bytes():
        print("It matches the original in the archive exactly.")
        return 0
    print(f"It does NOT match the original in the archive ({archived})!", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
