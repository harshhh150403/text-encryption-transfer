# Text encryption transfer

Encrypts files that arrive in `Source/` with PGP so that only SBI can read them, and puts the encrypted copy in `Sink/`. The original is then moved to `Source/archive/`.

```
Source/SBI_SBIN55_20261014_0002.txt
  ├─► Sink/SBI_SBIN55_20261014_0002.txt.pgp         encrypted with SBI's public key
  └─► Source/archive/SBI_SBIN55_20261014_0002.txt   the original, unencrypted
```

The pipeline only ever holds SBI's **public** key. Only SBI's private key can decrypt the `.pgp` files, so nobody on our side can open them; our readable copy is the one in the archive.

## How files are handled

- Files are encrypted as SBI specified: AES256, no compression, no signature, ASCII-armored. The `.pgp` file is therefore text starting with `-----BEGIN PGP MESSAGE-----`. Each of these can be changed in `.env` (`CIPHER_ALGO`, `COMPRESSION`, `SIGNING_KEY_FINGERPRINT`, `ARMOR`); the pipeline logs the format it uses at startup.

- Only files whose names match `FILE_PATTERN` (default `SBI_*.txt`) are picked up. Everything else is ignored, including temporary names such as `.part` or `.tmp`.
- A file is picked up once it hasn't changed for `STABLE_SECONDS` and, on Windows, no other program still has it open for writing. The safest setup is for whatever drops files into Source to write them under a temporary name and rename them when finished.
- The encrypted file is written as `<name>.pgp.part` and renamed when complete, so anything reading Sink never sees half a file.
- Nothing in Sink or the archive is ever overwritten. If a name is already taken, the file stays in Source and an error is logged.
- A file that fails stays in Source and is retried after `RETRY_SECONDS`, or as soon as it changes.
- Only one copy of the pipeline can run on the same folders at a time.
- At startup every key is checked: missing, expired or revoked keys stop the pipeline, keys expiring within 30 days are warned about, and keys that would produce files only GnuPG can decrypt are refused (see [SBI&#39;s key](#sbis-key)).

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
```

Then copy the sample file into `Source`, which is what a new file arriving looks like. The sample is kept in `samples/` so the pipeline never moves it; `Source/` and `Sink/` are kept out of git.

```bat
:: Windows
copy samples\SBI_SBIN55_20261014_0002.txt Source\
```

```bash
# macOS
cp samples/SBI_SBIN55_20261014_0002.txt Source/
```

Encrypt it, then decrypt it the way SBI will:

```
python main.py --once
python scripts/decrypt_file.py Sink/SBI_SBIN55_20261014_0002.txt.pgp
```

The last command also checks the decrypted file against the original in the archive.

To run the same test again, delete the encrypted file and the archived original, then copy the sample in again:

```bat
:: Windows
del Sink\SBI_SBIN55_20261014_0002.txt.pgp Source\archive\SBI_SBIN55_20261014_0002.txt
copy samples\SBI_SBIN55_20261014_0002.txt Source\
```

```bash
# macOS
rm Sink/SBI_SBIN55_20261014_0002.txt.pgp Source/archive/SBI_SBIN55_20261014_0002.txt
cp samples/SBI_SBIN55_20261014_0002.txt Source/
```

## Running

```
python main.py           # watch Source and encrypt each file as it arrives (Ctrl+C to stop)
python main.py --once    # encrypt the files waiting now, then exit
```

Logs go to the console and to `logs/pipeline.log`. Exit codes: `0` success, `1` a file failed or another copy is already running, `2` a setup problem (settings, GnuPG or keys).

## SBI's key

SBI sends us its **public** key and keeps the private key. Import it with:

```
python scripts/import_public_key.py "SBI Public Key/uat_NextGen_SBI_public.asc (1).txt"
```

The quotes are needed because the file name contains spaces. The script lists every key in the file, with its fingerprint and expiry date, and whether it can be used. It refuses any file that contains a private key.

Then:

1. **Pick one key.** A file can hold several keys; SBI's UAT file holds four. Ask SBI which one to use.
2. **Confirm its fingerprint with SBI by phone,** so you know nobody swapped the key on the way.
3. **Set it in `.env`:** `RECIPIENT_FINGERPRINTS=<that fingerprint>`.
4. **Watch the expiry date.** The pipeline warns 30 days before the key expires, and stops encrypting once it has.

### Keys that ask for OCB

Keys created by recent GnuPG or Kleopatra versions, SBI's UAT keys among them, ask gpg to encrypt in its newer OCB format. gpg then always does, whatever options it's given. GnuPG 2.3+ and Kleopatra can decrypt OCB files, but many other PGP programs can't, so the pipeline refuses such a key at startup. There are two ways forward:

- **SBI confirms that its software decrypts OCB,** for example by decrypting a UAT test file. Then set `ALLOW_GNUPG_ONLY_FORMAT=true` in `.env`.
- **SBI removes OCB from its key's preferences** and sends us the public key again. Files then use the classic format that every PGP program reads. In GnuPG, the key's owner runs `gpg --edit-key <fingerprint>`, then `setpref AES256 AES192 AES SHA512 SHA384 SHA256 Uncompressed ZLIB ZIP`, answers `y`, and enters `save`. This changes only the key's preferences: the key and its fingerprint stay the same. We then import the re-sent public key with the import script as before.

### Creating a key pair for a recipient

SBI supplies its own key, so this is only needed for rehearsals, or if a recipient ever asks us to create its key. Use the script below on a trusted company computer, not on the pipeline server. Don't use Kleopatra's "New Key Pair": its keys ask for OCB (see above). The script creates the key without it.

```
python scripts/create_recipient_key.py --name "SBI - <company> file exchange" --email <SBI contact email>
```

It asks for a passphrase and writes three files to `key_handover/`:

| File                           | What to do with it                                                                             |
| ------------------------------ | ---------------------------------------------------------------------------------------------- |
| `public_key.asc`             | Keep. Import it into the pipeline as shown above; it is the only file that goes to the server. |
| `PRIVATE_KEY.asc`            | Give to SBI only. It is protected by the passphrase.                                           |
| `revocation_certificate.asc` | Give to SBI. It lets them cancel the key if it ever leaks.                                     |

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
<public key file></public>
