# GPG Verifier

Aplikasi Android untuk memverifikasi GPG signature dan mengelola keyring.  
Dibangun dengan Kotlin + Jetpack Compose. Build otomatis via GitHub Actions.

## Fitur

- Verifikasi file dengan signature `.sig` / `.asc`
- Import public key dari file atau keyserver
- Manajemen keyring: list, delete, trust, export key
- Raw GPG output tersedia untuk debugging
- Dark theme, Material 3

---

## Setup GitHub Actions (Wajib)

### 1. Buat Keystore untuk Signing

Di Termux atau PC:

```bash
keytool -genkeypair \
  -keystore my-release-key.jks \
  -alias gpgverifier \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000
```

### 2. Encode Keystore ke Base64

```bash
base64 -w 0 my-release-key.jks > keystore_b64.txt
cat keystore_b64.txt
```

### 3. Tambahkan GitHub Secrets

Buka repo → Settings → Secrets and variables → Actions → New repository secret

| Secret Name | Nilai |
|---|---|
| `KEYSTORE_BASE64` | Isi dari `keystore_b64.txt` |
| `KEYSTORE_PASSWORD` | Password keystore yang Anda buat |
| `KEY_ALIAS` | Alias key (contoh: `gpgverifier`) |
| `KEY_PASSWORD` | Password key (biasanya sama dengan keystore) |

### 4. Sediakan GPG Binary ARM

**Cara termudah (dari Termux Anda):**

```bash
# Di Termux
cp $(which gpg) /path/to/gpg-verifier/app/src/main/assets/gpg

# Lalu commit
git add app/src/main/assets/gpg
git commit -m "Add GPG binary for armeabi-v7a"
git push
```

GitHub Actions akan otomatis mencoba download dari Termux repository jika binary tidak ada.

---

## Build & Release

### Build biasa (upload artifact)
```bash
git push origin main
```
APK tersedia di Actions → artifact.

### Buat release resmi
```bash
git tag v1.0.0
git push origin v1.0.0
```
APK akan otomatis muncul di GitHub Releases.

---

## Struktur Proyek

```
app/src/main/
├── assets/
│   └── gpg                    ← Binary GPG armeabi-v7a
├── java/com/gpgverifier/
│   ├── MainActivity.kt        ← Entry point + navigasi
│   ├── executor/
│   │   └── GpgExecutor.kt     ← ProcessBuilder wrapper GPG
│   ├── keyring/
│   │   └── KeyringRepository.kt ← Repository layer
│   ├── model/
│   │   └── Models.kt          ← Data classes
│   └── ui/
│       ├── screens/
│       │   ├── VerifyScreen.kt   ← UI verifikasi
│       │   └── KeyringScreen.kt  ← UI manajemen key
│       └── theme/
│           └── Theme.kt       ← Material3 dark theme
└── res/
    ├── drawable/ic_launcher.xml
    └── values/
        ├── strings.xml
        └── themes.xml
```

---

## Cara Pakai Aplikasi

### Verifikasi File
1. Tab **Verify**
2. Pilih file yang ingin diverifikasi
3. Pilih file signature (`.sig` atau `.asc`)
4. Tap **Verify Signature**
5. Hasil muncul: ✅ VALID atau ❌ INVALID

### Import Key
- Tab **Keyring** → tombol **+** → pilih file `.asc` / `.gpg`
- Atau tap ikon cloud → import dari keyserver dengan Key ID

### Set Trust Level
- Di Keyring, expand key → tap **Trust** → pilih level

---

## Catatan Teknis

- GPG binary diextract ke `filesDir` saat pertama kali dijalankan
- GNUPGHOME disimpan di `filesDir/.gnupg` (private, tidak perlu permission)
- Tidak ada koneksi internet selain saat import dari keyserver
- Min SDK: Android 8.0 (API 26)
- ABI: armeabi-v7a
