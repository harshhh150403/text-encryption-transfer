# Text encryption transfer

Encrypts files that arrive in `Source/` with PGP so that only SBI can read them, and puts the encrypted copy in `Sink/`. The original is then moved to `Source/archive/`.

```
Source/SBI_SBIN55_20261014_0002.txt
  ├─► Sink/SBI_SBIN55_20261014_0002.txt.pgp         encrypted with SBI's public key
  └─► Source/archive/SBI_SBIN55_20261014_0002.txt   the original, unencrypted
```

The pipeline only ever holds SBI's **public** key. Only SBI's private key can decrypt the `.pgp` files, so nobody on our side can open them; our readable copy is the one in the archive.

## How files are handled

- Only files whose names match `FILE_PATTERN` (default `SBI_*.txt`) are picked up. Everything else is ignored, including temporary names such as `.part` or `.tmp`.
- A file is picked up once it hasn't changed for `STABLE_SECONDS` and, on Windows, no other program still has it open for writing. The safest setup is for whatever drops files into Source to write them under a temporary name and rename them when finished.
- The encrypted file is written as `<name>.pgp.part` and renamed when complete, so anything reading Sink never sees half a file.
- Nothing in Sink or the archive is ever overwritten. If a name is already taken, the file stays in Source and an error is logged.
- A file that fails stays in Source and is retried after `RETRY_SECONDS`, or as soon as it changes.
- Only one copy of the pipeline can run on the same folders at a time.
- At startup every key is checked: missing, expired or revoked keys stop the pipeline, keys expiring within 30 days are warned about, and keys that would produce files only GnuPG can decrypt are refused (see [SBI's key](#sbis-key)).

## Setup

You need Python 3.11 or newer and GnuPG.

**Windows** (office laptop and server): install [Gpg4win](https://gpg4win.org) and [Python](https://www.python.org/downloads/), then run this in Command Prompt from the project folder:

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

PowerShell may block the `activate` step because of its script execution policy; Command Prompt doesn't.

**macOS**:

```bash
brew install gnupg
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Settings live in `.env`. Every setting is listed with an explanation in `.env.example`, and the test-key script below creates `.env` for you. On Windows, write paths without quotes, for example `SOURCE_DIR=D:\pipeline\Source`.

The pipeline keeps its keys in its own keyring folder, `gnupg_home/`, so they don't appear in Kleopatra.

## Try it with a test key

Until SBI's key is in place, a throwaway test key pair stands in for SBI. Its private key is kept in `test_keys/recipient/`, which plays the part of SBI's computer.

```
python scripts/setup_test_keys.py
python main.py --once
python scripts/decrypt_file.py Sink/SBI_SBIN55_20261014_0002.txt.pgp
```

The last command decrypts the file the way SBI will, and checks it against the original in the archive.

To run the same test again, move the original back and delete the encrypted file:

```bat
:: Windows
move Source\archive\SBI_SBIN55_20261014_0002.txt Source\
del Sink\SBI_SBIN55_20261014_0002.txt.pgp
```

```bash
# macOS
mv Source/archive/SBI_SBIN55_20261014_0002.txt Source/
rm Sink/SBI_SBIN55_20261014_0002.txt.pgp
```

## Running

```
python main.py           # watch Source and encrypt each file as it arrives (Ctrl+C to stop)
python main.py --once    # encrypt the files waiting now, then exit
```

Logs go to the console and to `logs/pipeline.log`. Exit codes: `0` success, `1` a file failed or another copy is already running, `2` a setup problem (settings, GnuPG or keys).

## SBI's key

**If SBI sends you its public key**, import it and confirm the printed fingerprint with SBI by phone:

```
python scripts/import_public_key.py path\to\sbi_public_key.asc
```

Then set `RECIPIENT_FINGERPRINTS` in `.env` to that fingerprint, replacing the test key's. The import script refuses any file that contains a private key.

**If you create the key pair for SBI**, use the script below on a trusted company computer, not on the pipeline server. Don't use Kleopatra's "New Key Pair": keys made by recent Kleopatra and GnuPG versions make gpg encrypt in a newer format (OCB) that most PGP programs other than GnuPG can't decrypt. The script creates the key with settings that avoid it.

```
python scripts/create_recipient_key.py --name "SBI - <company> file exchange" --email <SBI contact email>
```

It asks for a passphrase and writes three files to `key_handover/`:

| File | What to do with it |
|---|---|
| `public_key.asc` | Keep. Import it into the pipeline as shown above; it is the only file that goes to the server. |
| `PRIVATE_KEY.asc` | Give to SBI only. It is protected by the passphrase. |
| `revocation_certificate.asc` | Give to SBI. It lets them cancel the key if it ever leaks. |

1. Import `public_key.asc` into the pipeline.
2. Send `PRIVATE_KEY.asc` and `revocation_certificate.asc` through one channel (for example SBI's secure upload, or in person), and the passphrase through a different one (for example a phone call to a known contact).
3. Ask SBI to read the key's fingerprint back to you after importing it.
4. Send a test file and have SBI confirm it opens.
5. Delete `key_handover/`, so no copy of the private key remains on our side.

## Tests

```
python -m unittest
```

The tests use real GnuPG with throwaway keys and temporary folders.
