"""Encrypt a test file the way SBI will, and drop it into the decryption pipeline's source folder.

    python scripts/encrypt_like_sbi.py                     the sample file
    python scripts/encrypt_like_sbi.py path/to/file.txt    any file

Like SBI, it uses only our public key. The file is encrypted for our key in SBI's format
(ASCII-armored, AES256, not compressed, not signed) and saved as <name>.pgp, ready for:

    python main.py decrypt --once
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

from pipeline.config import PROJECT_DIR, ConfigError, load_decryption_settings
from pipeline.encryptor import ENCRYPTED_SUFFIX
from pipeline.gpg import PgpError, describe_key, gpg_messages, key_problem, open_keyring

SAMPLE_FILE = PROJECT_DIR / "samples" / "SBI_SBIN55_20261014_0002.txt"


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt a test file for our key, the way SBI will.")
    parser.add_argument("file", type=Path, nargs="?", default=SAMPLE_FILE, help="the file to encrypt")
    args = parser.parse_args()

    if not args.file.is_file():
        print(f"File not found: {args.file}", file=sys.stderr)
        return 1
    try:
        settings = load_decryption_settings()
        gpg = open_keyring(settings.gnupg_home, settings.gpg_binary)
    except (ConfigError, PgpError) as exc:
        print(exc, file=sys.stderr)
        return 1
    our_keys = [key for key in gpg.list_keys(secret=True) if not key_problem(key)]
    if not our_keys:
        print("There is no usable key of ours yet. Create it with scripts/create_decryption_key.py", file=sys.stderr)
        return 1
    inbound = settings.job.source_dir
    if not inbound.is_dir():
        print(f"The folder {inbound} does not exist. Create it, or check DECRYPT_SOURCE_DIR in .env.", file=sys.stderr)
        return 1
    output = inbound / (args.file.name + ENCRYPTED_SUFFIX)
    if output.exists():
        print(f"{output} already exists.", file=sys.stderr)
        return 1

    # Written under a hidden name first, which the pipeline ignores, so it never sees half a file.
    temporary = inbound / f".{output.name}.tmp"
    result = gpg.encrypt_file(
        str(args.file),
        [our_keys[0]["fingerprint"]],
        always_trust=True,
        armor=True,
        output=str(temporary),
        extra_args=["--cipher-algo", "AES256", "--compress-algo", "none"],
    )
    if not result.ok:
        temporary.unlink(missing_ok=True)
        print(f"GnuPG could not encrypt {args.file.name}: {gpg_messages(result.stderr)}", file=sys.stderr)
        return 1
    os.replace(temporary, output)
    print(f"Encrypted {args.file.name} for {describe_key(our_keys[0])}")
    print(f"  -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
