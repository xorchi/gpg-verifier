# GPG Verifier

An Android application for GPG cryptographic operations — verify signatures, sign files, encrypt, decrypt, and manage your keyring — all on-device.

Built with **Kotlin + Jetpack Compose**. Uses [Bouncy Castle](https://www.bouncycastle.org/) as the cryptographic engine. No external GPG binary required.

> **Minimum SDK:** Android 8.0 (API 26)  
> **Build:** Automated via GitHub Actions → APK available under [Releases](../../releases)
>
> **Latest Release:** [v1.0.3](https://github.com/xorchi/gpg-verifier/releases/tag/v1.0.3)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Building the App](#building-the-app)
- [Usage Guide](#usage-guide)
- [Verifying a Release APK](#verifying-a-release-apk)
- [Technical Notes](#technical-notes)

---

## Features

| Feature | Description |
|---|---|
| **Verify** | Verify a detached `.sig` / `.asc` signature against the original file |
| **Verify ClearSign** | Verify and extract the message from a clearsign `.asc` file |
| **Sign** | Sign files using a secret key — detach armored, detach binary, clearsign, or embedded |
| **Encrypt** | Encrypt a file to one or more recipients using their public keys |
| **Encrypt Symmetric** | Encrypt a file with a passphrase only — no key pair required |
| **Decrypt** | Decrypt files encrypted with a public key or a symmetric passphrase |
| **Keyring** | Full keyring management: import, export, delete, set trust level |
| **Key Generation** | Generate RSA key pairs (2048 / 4096 bit) with optional expiry and passphrase |
| **Keyserver Import** | Import public keys directly from HKP/HKPS keyservers (e.g. `keys.openpgp.org`) |

---

## Architecture

```
┌─────────────────────────────────────┐
│           Jetpack Compose UI               │
│  VerifyScreen  SignEncryptScreen           │
│  DecryptScreen  KeyringScreen              │
└──────────────┬──────────────────────┘
                  │
┌──────────────▼──────────────────────┐
│         KeyringRepository                   │
│  (coroutine dispatcher, URI → File)        │
└──────────────┬──────────────────────┘
                  │
┌──────────────▼──────────────────────┐
│           GpgExecutor                       │
│  Pure Bouncy Castle implementation          │
│  verify / sign / encrypt / decrypt          │
│  generateKey / importKey / trustKey         │
└──────────────┬──────────────────────┘
                  │
┌──────────────▼──────────────────────┐
│    Internal Storage (filesDir)              │
│  keyring/pubring.pgp                        │
│  keyring/secring.pgp                        │
│  keyring/trustdb.txt                        │
│  logs/app.log                               │
└─────────────────────────────────────┘
```

**Key design decisions:**

- All cryptographic operations are performed by Bouncy Castle (`bcpg-jdk18on` + `bcprov-jdk18on`). No shell process or native binary is spawned.
- The Bouncy Castle provider is force-registered at position 1 via `Security.removeProvider("BC")` + `Security.insertProviderAt(...)` to prevent conflicts with Android's built-in BC provider (which is a stripped-down fork and does not support all algorithms).
- Keyrings are stored in the app's private internal storage — no `READ_EXTERNAL_STORAGE` permission is needed for core operations.
- File output (signed, encrypted, decrypted files) is written to `cacheDir` and shared via `FileProvider` + Android's Storage Access Framework (`ACTION_CREATE_DOCUMENT`). No legacy `WRITE_EXTERNAL_STORAGE` path.

---

## Project Structure

```
gpg-verifier
├── LICENSE
├── README.md
├── RELEASE_NOTES.md
├── app
│   ├── build.gradle.kts
│   ├── proguard-rules.pro
│   └── src
│       └── main
│           ├── AndroidManifest.xml
│           ├── java
│           │   └── com
│           │       └── gpgverifier
│           │           ├── MainActivity.kt
│           │           ├── MainActivity.kt.bak
│           │           ├── executor
│           │           │   └── GpgExecutor.kt
│           │           ├── keyring
│           │           │   └── KeyringRepository.kt
│           │           ├── model
│           │           │   └── Models.kt
│           │           ├── prefs
│           │           │   └── AppPreferences.kt
│           │           ├── ui
│           │           │   ├── screens
│           │           │   │   ├── AboutScreen.kt
│           │           │   │   ├── AppearanceScreen.kt
│           │           │   │   ├── DecryptScreen.kt
│           │           │   │   ├── KeyringScreen.kt
│           │           │   │   ├── SettingsScreen.kt
│           │           │   │   ├── SharedComponents.kt
│           │           │   │   ├── SignEncryptScreen.kt
│           │           │   │   ├── TextViewerScreen.kt
│           │           │   │   └── VerifyScreen.kt
│           │           │   └── theme
│           │           │       └── Theme.kt
│           │           └── util
│           │               ├── AppLogger.kt
│           │               └── FileShareHelper.kt
│           ├── jniLibs
│           │   └── armeabi-v7a
│           └── res
│               ├── drawable
│               │   ├── ic_launcher.xml
│               │   ├── ic_launcher_background.xml
│               │   └── ic_launcher_foreground.xml
│               ├── mipmap-anydpi-v26
│               │   └── ic_launcher.xml
│               ├── values
│               │   ├── strings.xml
│               │   └── themes.xml
│               ├── values-in
│               │   └── strings.xml
│               └── xml
│                   └── file_provider_paths.xml
├── build.gradle.kts
├── docs
│   └── xorchi-gpg-pubkey.asc
├── gradle
│   ├── libs.versions.toml
│   └── wrapper
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── gradlew
├── scripts
└── settings.gradle.kts
```

---

## Building the App

### Prerequisites

- A GitHub account with Actions enabled
- A signing keystore (JKS format)

### Step 1 — Generate a Release Keystore

Run this once on your machine or in Termux:

```bash
keytool -genkeypair \
  -keystore release.jks \
  -alias gpgverifier \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -dname "CN=GPGVerifier, O=Personal, C=ID"
```

### Step 2 — Encode the Keystore to Base64

```bash
base64 -w 0 release.jks
```

Copy the output — you will need it in the next step.

### Step 3 — Add GitHub Secrets

Navigate to your repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Secret Name | Value |
|---|---|
| `KEYSTORE_BASE64` | Base64-encoded output from Step 2 |
| `KEYSTORE_PASSWORD` | The password you set for the keystore |
| `KEY_ALIAS` | The alias you chose (e.g. `gpgverifier`) |
| `KEY_PASSWORD` | The key password (usually same as keystore password) |

### Step 4 — Push and Build

```bash
git push origin master
```

The workflow in `.github/workflows/build.yml` will automatically:
1. Set up JDK 17 and Android SDK
2. Decode the keystore from secrets
3. Build and sign the release APK
4. Upload the APK as a workflow artifact (retained for 7 days)

To produce a permanent GitHub Release, tag the commit:

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Usage Guide

### Verify a Signature

1. Open the **Verify** tab
2. Tap **File to Verify** → select the original file
3. Tap **Signature File** → select the `.sig` or `.asc` file
4. Tap **Verify Signature**
5. Result: ✅ VALID SIGNATURE or ❌ INVALID SIGNATURE, with signer UID, fingerprint, timestamp, and trust level

### Sign a File

1. Open the **Sign** tab
2. Select the input file
3. Choose a signing key from your secret keyring
4. Select a signature mode:

| Mode | Output | Use case |
|---|---|---|
| Detach armored | `.sig.asc` | Standard, human-readable, most compatible |
| Detach binary | `.sig` | Compact binary signature |
| Clearsign | `.asc` | Inline signature for plain-text files |
| Embedded armored | `.gpg.asc` | Signed + compressed, armored |
| Embedded binary | `.gpg` | Signed + compressed, binary |

Available hash algorithms: **SHA-256** (default), **SHA-512**

5. Enter the key passphrase
6. Tap **Sign** → save or share the output file

### Encrypt a File

1. Open the **Encrypt** tab
2. Select the input file
3. Select one or more recipients from your public keyring
4. Toggle armored (`.asc`) or binary (`.gpg`) output
5. Tap **Encrypt** → save or share the output

For passphrase-only encryption (no key pair required), use the **Sym. Encrypt** tab.

### Decrypt a File

1. Open the **Decrypt** tab
2. Select the encrypted file (`.gpg` or `.asc`)
3. Enter your passphrase
4. Tap **Decrypt** → save or share the decrypted output

Both public-key and symmetric-encrypted files are supported automatically.

### Manage Keys

From the **Keys** tab:

- **Import from file** — tap **+**, select a `.asc` or `.gpg` key file
- **Import from keyserver** — tap the cloud icon, enter a Key ID, fingerprint, or email
- **Export** — expand a key card → **Export Pub** (copies armored public key to clipboard) or **Export Secret Key**
- **Set trust** — expand a key card → **Trust** → choose a trust level (Unknown / None / Marginal / Full / Ultimate)
- **Delete** — expand a key card → **Delete Key** (confirmation required)

### Generate a Key Pair

From the **Keys** tab, tap the key icon → fill in:

| Field | Notes |
|---|---|
| Name | Your real name or alias |
| Email | Associated email address |
| Comment | Optional (e.g. `personal`) |
| Key Size | 2048 or 4096 — use 4096 for stronger keys |
| Expiry | Days until expiry, `0` = never expires |
| Passphrase | Leave blank for no passphrase (not recommended) |

Tap **Generate**. Both a primary signing key and an encryption subkey are created automatically.

---

## Verifying a Release APK

All official APK releases are GPG-signed by the developer. You can verify the authenticity of any release before installing it.

### Developer's Public GPG Key

The public key is included in this repository at:

```
docs/xorchi-gpg-pubkey.asc
```

**Fingerprint:**
```
DD88 E7E1 4A5A 892D 5DC5  D4A4 4B49 5F62 CBB3 7CFF

```

### How to Verify

**1. Import the developer's public key**

From the repository file:
```bash
gpg --import docs/xorchi-gpg-pubkey.asc
```

Or directly from a keyserver:
```bash
gpg --keyserver hkps://keyserver.ubuntu.com \
    --recv-keys 4B495F62CBB37CFF
```

**2. Download the APK and its detached signature**

From the [Releases](../../releases) page, download both files:
- `GPG-Verifier.apk`
- `GPG-Verifier.apk.asc`

**3. Run the verification**

```bash
gpg --verify GPG-Verifier.apk.asc GPG-Verifier.apk
```

**Expected output (good signature):**
```
gpg: Signature made <date> using EDDSA key 4B495F62CBB37CFF
gpg: Good signature from "xorchi <jperkasa8@gmail.com>"
```

> ⚠️ Any result other than `Good signature` means the file was not signed by this developer or has been modified after signing. **Do not install it.**

---

## Technical Notes

### Bouncy Castle Provider Conflict

Android ships a stripped-down fork of Bouncy Castle registered under the name `"BC"`. Calling `Security.addProvider(new BouncyCastleProvider())` is silently ignored when that name is already taken, causing `NoSuchAlgorithmException` and `KeyFactory` errors at runtime on Android P+.

This app resolves the conflict explicitly:

```kotlin
Security.removeProvider("BC")
Security.insertProviderAt(BouncyCastleProvider(), 1)
```

This ensures the full Bouncy Castle library is active for all cryptographic operations.

### Key Storage

All keyring data is stored in the app's private internal storage, inaccessible to other apps:

| Path | Contents |
|---|---|
| `filesDir/keyring/pubring.pgp` | Public key ring collection |
| `filesDir/keyring/secring.pgp` | Secret key ring collection |
| `filesDir/keyring/trustdb.txt` | Per-fingerprint trust level assignments |

### Output File Handling

Operation outputs are written to `cacheDir` and surfaced to the user via:
- **Share** — Android share sheet via `FileProvider` (no storage permission required)
- **Save** — `ACTION_CREATE_DOCUMENT` (SAF), user selects destination folder

### Logging

Logs are written to `filesDir/logs/app.log` (app-private, no storage permission required) and mirrored to logcat under the tag `GPGVerifier`. The log file auto-rotates at 512 KB. Nothing is written to public storage (`/sdcard/Download` or similar).

### Permissions

| Permission | When used |
|---|---|
| `INTERNET` | Keyserver import only |
| `MANAGE_EXTERNAL_STORAGE` (Android 11+) | Optional — only if user opens files from arbitrary locations |
| `READ/WRITE_EXTERNAL_STORAGE` (≤ API 28) | Legacy file access for older devices |

### Dependencies

| Library | Version | Purpose |
|---|---|---|
| `bcpg-jdk18on` | 1.78.1 | OpenPGP packet layer |
| `bcprov-jdk18on` | 1.78.1 | Cryptographic provider |
| `androidx.compose.bom` | 2024.10.00 | Jetpack Compose UI |
| `androidx.navigation.compose` | 2.8.3 | In-app navigation |
| `androidx.documentfile` | 1.0.1 | SAF file access |

---

## Support

If you find this project useful, consider supporting its development:

**Bitcoin**

bc1quhmeps5t8v6d4c9pr5k2jg2tl8flvvmevuwhtr

**Monero**

88fw7kpZbjmP2xhHjpsbfHAe3xQzkXKz83cY97qta7kK58J8aNynVA59Apn1dnUCdqdaNKAbmqkgDDtUfFZXAPPEHGyc2Ui

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file included in this repository.
