"""Decrypt a file from Sink with the TEST key, to check the pipeline end to end. TEST ONLY.

This does what SBI will do with its own private key. The decrypted copy goes to test_keys/decrypted/
and is compared with the original in the archive.

    python scripts/decrypt_file.py Sink/SBI_SBIN55_20261014_0002.pgp.txt
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import ConfigError, load_encryption_settings
from pipeline.decryptor import decrypted_file_name
from pipeline.encryptor import encrypted_file_name
from pipeline.gpg import PgpError, open_keyring
from scripts.setup_test_keys import RECIPIENT_KEYRING, TEST_KEYS_DIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt an encrypted file from Sink with the test key.")
    parser.add_argument("encrypted_file", type=Path)
    args = parser.parse_args()

    if not args.encrypted_file.is_file():
        print(f"File not found: {args.encrypted_file}", file=sys.stderr)
        return 1
    if not RECIPIENT_KEYRING.is_dir():
        print("No test key yet. Run: python scripts/setup_test_keys.py", file=sys.stderr)
        return 1
    try:
        settings = load_encryption_settings()
        gpg = open_keyring(RECIPIENT_KEYRING, settings.gpg_binary)
    except (ConfigError, PgpError) as exc:
        print(exc, file=sys.stderr)
        return 1

    # The original in the archive is the file whose encrypted name this is.
    archive = settings.job.archive_dir
    archived = next(
        (
            path for path in sorted(archive.iterdir() if archive.is_dir() else [])
            if path.is_file() and encrypted_file_name(path.name, settings.file_name) == args.encrypted_file.name
        ),
        None,
    )
    original_name = archived.name if archived else decrypted_file_name(args.encrypted_file.name)
    output = TEST_KEYS_DIR / "decrypted" / original_name
    output.parent.mkdir(parents=True, exist_ok=True)
    result = gpg.decrypt_file(str(args.encrypted_file), output=str(output))
    if not result.ok:
        print(f"Could not decrypt {args.encrypted_file.name}: {result.status}", file=sys.stderr)
        return 1
    print(f"Decrypted to {output}")
    if result.valid:
        print(f"Signed by {result.username}: the signature is valid")

    if archived is None:
        return 0
    if output.read_bytes() == archived.read_bytes():
        print("It matches the original in the archive exactly.")
        return 0
    print(f"It does NOT match the original in the archive ({archived})!", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
