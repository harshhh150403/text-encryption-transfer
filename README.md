# Text encryption transfer

Two PGP pipelines for exchanging files with SBI. Each watches a folder and handles every file that arrives.

**Encryption: files we send to SBI.** Files that arrive in `Source/` are encrypted with SBI's public key into `Sink/`, and the original is moved to `Source/archive/`.

```
Source/SBI_SBIN55_20261014_0002.txt
  ├─► Sink/SBI_SBIN55_20261014_0002.pgp.txt         encrypted with SBI's public key
  └─► Source/archive/SBI_SBIN55_20261014_0002.txt   the original, unencrypted
```

This pipeline only ever holds SBI's **public** key. Only SBI's private key can decrypt the encrypted files, so nobody on our side can open them; our readable copy is the one in the archive.

**Decryption: files SBI sends us.** SBI encrypts its files with **our public key**. Files that arrive in `Inbound/` are decrypted with our private key into `Decrypted/`, and the encrypted original is moved to `Inbound/archive/`.

```
Inbound/SBI_RESPONSE_0001.txt.pgp
  ├─► Decrypted/SBI_RESPONSE_0001.txt              decrypted with our private key
  └─► Inbound/archive/SBI_RESPONSE_0001.txt.pgp    the original, still encrypted
```

This pipeline holds **our private key**, in its own keyring, separate from the encryption pipeline's. See [Our key](#our-key-decryption) for how it is created and backed up.

The two pipelines share the code but run separately: each has its own settings, folders, keyring and log file, they can run at the same time, and stopping one doesn't stop the other.

## How files are handled

Both pipelines:

- Pick up only files whose names match their pattern (`FILE_PATTERN`, default `SBI_*.txt`; `DECRYPT_FILE_PATTERN`, default `*.pgp, *.gpg, *.asc, *.pgp.txt`). Everything else is ignored, including temporary names such as `.part` or `.tmp`, hidden files, and Office lock files.
- Pick up a file once it hasn't changed for `STABLE_SECONDS` and, on Windows, no other program still has it open for writing. The safest setup is for whatever drops files in to write them under a temporary name and rename them when finished.
- Write the new file as `<name>.part` and rename it when complete, so anything reading the output folder never sees half a file.
- Never overwrite anything in the output folder or the archive. If a name is already taken, the file stays where it is and an error is logged.
- Leave a file that fails where it is, and retry it after `RETRY_SECONDS`, or as soon as it changes.
- Refuse to run twice on the same folders at the same time.
- Check their keys at startup and stop, before touching any file, if something is wrong.

The encryption pipeline:

- Encrypts as SBI specified: AES256, no compression, no signature, ASCII-armored, and named like the original with its `.txt` replaced by `.pgp.txt`. The encrypted file is therefore text starting with `-----BEGIN PGP MESSAGE-----`. Each of these can be changed in `.env` (`CIPHER_ALGO`, `COMPRESSION`, `SIGNING_KEY_FINGERPRINT`, `ARMOR`, `ENCRYPTED_FILE_NAME`); the pipeline logs the format it uses at startup.
- At startup, refuses missing, expired or revoked keys, warns about keys expiring within 30 days, and refuses keys that would produce files only GnuPG can decrypt (see [SBI&#39;s key](#sbis-key-encryption)).

The decryption pipeline:

- Names the decrypted file like the encrypted one, without `.pgp`, `.gpg` or `.asc`, also when `.txt` follows: `SBI_X.pgp.txt` and `SBI_X.txt.pgp.txt` both become `SBI_X.txt`. Armored and binary files both work.
- Only accepts files encrypted for our key. Files encrypted for another key, with a password, or not at all, and damaged files, are refused and stay in the inbound folder. Nothing partly decrypted is left behind.
- At startup, checks that our private key is there and that `DECRYPT_KEY_PASSPHRASE` unlocks it.

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

Each pipeline keeps its keys in its own keyring folder (`gnupg_home/` and `gnupg_home_decrypt/`), so they don't appear in Kleopatra.

## Running

```
python main.py                  # encryption: watch Source, encrypt each file as it arrives (Ctrl+C to stop)
python main.py --once           # encryption: encrypt the files waiting now, then exit
python main.py decrypt          # decryption: watch the inbound folder, decrypt each file as it arrives
python main.py decrypt --once   # decryption: decrypt the files waiting now, then exit
```

Logs go to the console and to `logs/encrypt.log` or `logs/decrypt.log`. Exit codes: `0` success, `1` a file failed or another copy is already running, `2` a setup problem (settings, GnuPG or keys).

On the Windows server, each pipeline runs as its own Task Scheduler task, which starts it at boot and restarts it if it stops: program `<project>\.venv\Scripts\python.exe`, start in `<project>`, arguments `main.py` (encryption) or `main.py decrypt` (decryption).

## Try the encryption pipeline with a test key

Until SBI's key is in place, a throwaway test key pair stands in for SBI. Its private key is kept in `test_keys/recipient/`, which plays the part of SBI's computer.

```
python scripts/setup_test_keys.py
```

Then copy the sample file into `Source`, which is what a new file arriving looks like. The sample is kept in `samples/` so the pipeline never moves it; the pipelines' folders are kept out of git.

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
python scripts/decrypt_file.py Sink/SBI_SBIN55_20261014_0002.pgp.txt
```

The last command also checks the decrypted file against the original in the archive.

To run the same test again, delete the encrypted file and the archived original, then copy the sample in again:

```bat
:: Windows
del Sink\SBI_SBIN55_20261014_0002.pgp.txt Source\archive\SBI_SBIN55_20261014_0002.txt
copy samples\SBI_SBIN55_20261014_0002.txt Source\
```

```bash
# macOS
rm Sink/SBI_SBIN55_20261014_0002.pgp.txt Source/archive/SBI_SBIN55_20261014_0002.txt
cp samples/SBI_SBIN55_20261014_0002.txt Source/
```

## SBI's key (encryption)

SBI sends us its **public** key and keeps the private key. Import it with:

```
python scripts/import_public_key.py "SBI Public Key/uat_NextGen_SBI_public_noaead (1).asc"
```

The quotes are needed because the file name contains spaces. The script lists every key in the file, with its fingerprint and expiry date, and whether it can be used. It refuses any file that contains a private key.

Then:

1. **Pick one key.** A file can hold several keys; SBI's UAT file holds three. Ask SBI which one to use.
2. **Confirm its fingerprint with SBI by phone,** so you know nobody swapped the key on the way.
3. **Set it in `.env`:** `RECIPIENT_FINGERPRINTS=<that fingerprint>`.
4. **Watch the expiry date.** The pipeline warns 30 days before the key expires, and stops encrypting once it has.

**When SBI sends updated or new keys,** import the new file with `--replace`. It checks the new file first, then removes the SBI keys already in the keyring and imports the new ones:

```
python scripts/import_public_key.py --replace "SBI Public Key/<new file>"
```

Then check `RECIPIENT_FINGERPRINTS` (a key keeps its fingerprint when only its preferences change) and restart the encryption pipeline, which reads its keys only at startup.

### Keys that ask for OCB

Keys created by recent GnuPG or Kleopatra versions, SBI's UAT keys among them, ask gpg to encrypt in its newer OCB format. gpg then always does, whatever options it's given. GnuPG 2.3+ and Kleopatra can decrypt OCB files, but many other PGP programs can't, so the pipeline refuses such a key at startup. SBI's first UAT keys did this; its updated keys (`uat_NextGen_SBI_public_noaead`) don't. If a key asks for OCB, there are two ways forward:

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

## Our key (decryption)

The decryption pipeline needs our own key pair. Create it **on the server** where the decryption pipeline runs, so the private key never travels:

```
python scripts/create_decryption_key.py --name "<company> - SBI file exchange" --email <our contact email>
```

It asks for a passphrase, creates the key (RSA 4096, never expires) in `DECRYPT_GNUPG_HOME`, and writes three files to `key_export/`:

| File                           | What to do with it                                                              |
| ------------------------------ | ------------------------------------------------------------------------------- |
| `our_public_key.asc`         | Send to SBI, and confirm the fingerprint with them by phone.                    |
| `PRIVATE_KEY_BACKUP.asc`     | Give to IT for its secure vault. It is protected by the passphrase.             |
| `revocation_certificate.asc` | Give to IT for the vault. It cancels the key if the key is ever compromised.    |

Then:

1. **Set the passphrase in `.env`:** `DECRYPT_KEY_PASSPHRASE=<the passphrase>`. The script tells you whether to put it in single quotes (needed when it contains a `#` or starts or ends with a space). Store the passphrase separately from the backup too, for example in IT's password manager.
2. **Check it:** `python main.py decrypt --once` stops with a clear message if the key is missing or the passphrase is wrong.
3. **Delete `key_export/`** from the server once the files are with SBI and IT.
4. **Restrict access** to `DECRYPT_GNUPG_HOME`, `.env` and `DECRYPT_DESTINATION_DIR` to the account the pipeline runs as and administrators. The destination folder holds readable bank data.

**Keep the backup safe.** Without our private key, files SBI has encrypted for us can never be decrypted, and SBI would have to resend everything with a new key. To restore the key on a new server:

```
gpg --homedir <DECRYPT_GNUPG_HOME> --import PRIVATE_KEY_BACKUP.asc
```

and set `DECRYPT_KEY_PASSPHRASE` in `.env` again.

## Try the decryption pipeline

Once our key exists, this encrypts the sample file the way SBI will (with our public key, ASCII-armored, AES256, not compressed) and drops it into the inbound folder:

```
python scripts/encrypt_like_sbi.py
python main.py decrypt --once
```

The decrypted file appears in `Decrypted/`, and the encrypted original moves to `Inbound/archive/`. Create the `Inbound` folder first if it doesn't exist (or set `DECRYPT_SOURCE_DIR`).

## Tests

```
python -m unittest
```

The tests use real GnuPG with throwaway keys and temporary folders.
<public key file></public>
