#!/usr/bin/env bash
# setup_repo.sh
# Jalankan di Termux untuk inisialisasi repo dan copy GPG binary

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== GPG Verifier - Setup Repo ==="
echo ""

# ── Copy GPG binary dari Termux ───────────────────────────────────────────────
GPG_BIN=$(which gpg 2>/dev/null || which gpg2 2>/dev/null || echo "")
ASSETS_DIR="$REPO_DIR/app/src/main/assets"

mkdir -p "$ASSETS_DIR"

if [ -n "$GPG_BIN" ]; then
    echo "[1/3] Menyalin GPG binary dari $GPG_BIN..."
    cp "$GPG_BIN" "$ASSETS_DIR/gpg"
    chmod 755 "$ASSETS_DIR/gpg"
    echo "      ✓ GPG binary disalin ($(du -h "$ASSETS_DIR/gpg" | cut -f1))"
else
    echo "[1/3] ✗ GPG binary tidak ditemukan di PATH"
    echo "      Install dulu: pkg install gnupg"
    exit 1
fi

# ── Buat keystore jika belum ada ──────────────────────────────────────────────
echo ""
echo "[2/3] Keystore setup..."

KEYSTORE_DIR="$HOME/.gpgverifier"
mkdir -p "$KEYSTORE_DIR"
KEYSTORE_FILE="$KEYSTORE_DIR/release.jks"

if [ ! -f "$KEYSTORE_FILE" ]; then
    echo "      Membuat keystore baru..."
    read -p "      Alias key [gpgverifier]: " KEY_ALIAS
    KEY_ALIAS="${KEY_ALIAS:-gpgverifier}"

    keytool -genkeypair \
        -keystore "$KEYSTORE_FILE" \
        -alias "$KEY_ALIAS" \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=GPGVerifier, O=Personal, C=ID"

    echo ""
    echo "      Encode keystore ke base64 untuk GitHub Secrets:"
    echo "      ─────────────────────────────────────────────────"
    base64 -w 0 "$KEYSTORE_FILE"
    echo ""
    echo "      ─────────────────────────────────────────────────"
    echo "      Salin output di atas → GitHub Secret: KEYSTORE_BASE64"
else
    echo "      ✓ Keystore sudah ada di $KEYSTORE_FILE"
fi

# ── Git init ──────────────────────────────────────────────────────────────────
echo ""
echo "[3/3] Git setup..."

cd "$REPO_DIR"

if [ ! -d ".git" ]; then
    git init
    echo "      ✓ Git repo diinisialisasi"
fi

# Download gradle wrapper jar jika belum ada
WRAPPER_JAR="gradle/wrapper/gradle-wrapper.jar"
if [ ! -f "$WRAPPER_JAR" ]; then
    echo "      Mendownload gradle-wrapper.jar..."
    mkdir -p gradle/wrapper
    curl -sL "https://github.com/gradle/gradle/raw/v8.9.0/gradle/wrapper/gradle-wrapper.jar" \
         -o "$WRAPPER_JAR"
    echo "      ✓ gradle-wrapper.jar didownload"
fi

# Buat gradlew jika belum ada
if [ ! -f "gradlew" ]; then
    curl -sL "https://raw.githubusercontent.com/gradle/gradle/v8.9.0/gradlew" -o gradlew
    chmod +x gradlew
    echo "      ✓ gradlew dibuat"
fi

echo ""
echo "=== ✓ Setup selesai! ==="
echo ""
echo "Langkah selanjutnya:"
echo "  1. Buat repo di GitHub"
echo "  2. Tambahkan GitHub Secrets (lihat README.md)"
echo "  3. git add ."
echo "  4. git commit -m 'Initial commit'"
echo "  5. git remote add origin https://github.com/USERNAME/REPO.git"
echo "  6. git push origin main"
echo ""
echo "APK akan otomatis build di GitHub Actions!"
