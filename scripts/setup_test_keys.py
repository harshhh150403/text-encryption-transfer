"""Create a throwaway key pair that stands in for SBI, so the pipeline can be tried out. TEST ONLY.

The test key's private half goes into test_keys/recipient, which plays the part of SBI's
computer. The pipeline's own keyring only gets the public key, exactly as it will with SBI's real key.

    python scripts/setup_test_keys.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so the pipeline package can be imported

import gnupg

from pipeline.config import PROJECT_DIR, ConfigError, load_settings
from pipeline.encryptor import EncryptionError, create_key_pair, import_public_key, open_keyring

TEST_KEYS_DIR = PROJECT_DIR / "test_keys"
# The recipient's keyring. Kept short: on macOS, gpg's socket path inside it has a length limit.
RECIPIENT_KEYRING = TEST_KEYS_DIR / "recipient"
PUBLIC_KEY_FILE = TEST_KEYS_DIR / "test_recipient_public.asc"
ENV_FILE = PROJECT_DIR / ".env"
ENV_EXAMPLE_FILE = PROJECT_DIR / ".env.example"


def main() -> int:
    try:
        settings = load_settings()
        recipient_gpg = open_keyring(RECIPIENT_KEYRING, settings.gpg_binary)
        fingerprint = _test_key(recipient_gpg)
        PUBLIC_KEY_FILE.write_text(recipient_gpg.export_keys(fingerprint), encoding="utf-8")
        import_public_key(open_keyring(settings.gnupg_home, settings.gpg_binary), PUBLIC_KEY_FILE)
    except (ConfigError, EncryptionError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print(f"\nTest key fingerprint: {fingerprint}")
    print(f"  private key (plays SBI's computer): {RECIPIENT_KEYRING}")
    print(f"  public key, imported into the pipeline's keyring: {PUBLIC_KEY_FILE}")
    if _set_recipient_in_env(fingerprint):
        print(f"  {ENV_FILE.name}: RECIPIENT_FINGERPRINTS is set to the test key")
    else:
        print(f"  {ENV_FILE.name} already lists another recipient. To use the test key, set:")
        print(f"  RECIPIENT_FINGERPRINTS={fingerprint}")
    print("\nNext:")
    print("  python main.py --once")
    print("  python scripts/decrypt_file.py Sink/<file name>.pgp")
    return 0


def _test_key(gpg: gnupg.GPG) -> str:
    """Fingerprint of the test key, created on the first run."""
    existing = gpg.list_keys(secret=True)
    if existing:
        print("The test key already exists; reusing it.")
        return existing[0]["fingerprint"]
    print("Creating the test key pair (RSA 3072, no passphrase: for testing only)...")
    # Created the same way as SBI's real key should be (see create_recipient_key.py).
    return create_key_pair(
        gpg, "TEST ONLY - stand-in for SBI", "test-recipient@example.invalid", None, key_length=3072, expires="1y"
    )


def _set_recipient_in_env(fingerprint: str) -> bool:
    """Put the test key in RECIPIENT_FINGERPRINTS in .env (created from .env.example if missing).

    Returns False if the setting already holds a different key, which is left alone.
    """
    if not ENV_FILE.exists():
        ENV_FILE.write_text(ENV_EXAMPLE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines):
        name, _, value = line.partition("=")
        if name.strip() == "RECIPIENT_FINGERPRINTS":
            current = value.replace(" ", "").strip().upper()
            if fingerprint in current:
                return True
            if current:
                return False
            lines[index] = f"RECIPIENT_FINGERPRINTS={fingerprint}\n"
            break
    else:
        lines.append(f"\nRECIPIENT_FINGERPRINTS={fingerprint}\n")
    ENV_FILE.write_text("".join(lines), encoding="utf-8")
    return True


if __name__ == "__main__":
    sys.exit(main())
