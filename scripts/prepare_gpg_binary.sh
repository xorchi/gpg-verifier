#!/usr/bin/env bash
# prepare_gpg_binary.sh
# Download GPG binary untuk armeabi-v7a dari Termux bootstrap
# Dijalankan oleh GitHub Actions sebelum build

set -euo pipefail

ASSETS_DIR="app/src/main/assets"
GPG_DEST="$ASSETS_DIR/gpg"
ARCH="arm"

mkdir -p "$ASSETS_DIR"

echo "==> Mencari GPG binary untuk armeabi-v7a..."

# ── Metode 1: Download dari Termux package repository ─────────────────────────
download_from_termux() {
    echo "    Mencoba download dari Termux repository..."

    # Install tools yang diperlukan
    sudo apt-get update -qq
    sudo apt-get install -y -qq wget binutils-multiarch file 2>/dev/null || true

    # Download Termux gnupg package untuk arm
    TERMUX_API="https://packages.termux.dev/apt/termux-main/dists/stable/main"
    PKG_LIST_URL="$TERMUX_API/binary-$ARCH/Packages.gz"

    echo "    Fetching package list dari $PKG_LIST_URL"
    wget -q "$PKG_LIST_URL" -O /tmp/Packages.gz
    gunzip -f /tmp/Packages.gz

    # Parse URL package gnupg
    PKG_URL=$(grep -A 20 "^Package: gnupg" /tmp/Packages | grep "^Filename:" | head -1 | awk '{print $2}')

    if [ -z "$PKG_URL" ]; then
        echo "    gnupg tidak ditemukan, mencoba gnupg2..."
        PKG_URL=$(grep -A 20 "^Package: gnupg2" /tmp/Packages | grep "^Filename:" | head -1 | awk '{print $2}')
    fi

    if [ -n "$PKG_URL" ]; then
        FULL_URL="https://packages.termux.dev/apt/termux-main/$PKG_URL"
        echo "    Downloading: $FULL_URL"
        wget -q "$FULL_URL" -O /tmp/gnupg.deb

        # Extract .deb
        mkdir -p /tmp/gnupg_extract
        cd /tmp/gnupg_extract
        ar x /tmp/gnupg.deb

        # Extract data archive
        if [ -f data.tar.xz ]; then
            tar xf data.tar.xz
        elif [ -f data.tar.gz ]; then
            tar xf data.tar.gz
        elif [ -f data.tar.zst ]; then
            tar xf data.tar.zst 2>/dev/null || zstd -d data.tar.zst -o data.tar && tar xf data.tar
        fi

        # Cari binary gpg
        GPG_BIN=$(find . -name "gpg" -o -name "gpg2" | grep -v ".pyc" | head -1)
        cd - > /dev/null

        if [ -n "$GPG_BIN" ]; then
            cp "/tmp/gnupg_extract/$GPG_BIN" "$GPG_DEST"
            echo "    ✓ GPG binary ditemukan dan disalin"
            return 0
        fi
    fi

    return 1
}

# ── Metode 2: Cross-compile dari source (fallback) ────────────────────────────
build_from_source() {
    echo "    Mencoba cross-compile dari source..."

    sudo apt-get install -y -qq \
        gcc-arm-linux-gnueabihf \
        pkg-config \
        wget \
        make \
        libgpg-error-dev \
        libassuan-dev 2>/dev/null || true

    # Ini butuh waktu lama, hanya fallback
    # Di sini kita simplify dengan static build minimal
    echo "    ⚠ Cross-compile tidak tersedia, gunakan metode alternatif"
    return 1
}

# ── Metode 3: Pakai GPG yang sudah ada di runner + strip ─────────────────────
use_system_gpg_shim() {
    echo "    ⚠ WARNING: Menggunakan shim script karena GPG binary ARM tidak tersedia"
    echo "    Ini TIDAK akan bekerja di Android! Harap sediakan binary ARM secara manual."

    cat > "$GPG_DEST" << 'SHIM'
#!/system/bin/sh
# GPG shim - replace this with actual armeabi-v7a GPG binary
echo "ERROR: Real GPG binary not installed" >&2
exit 127
SHIM
    chmod +x "$GPG_DEST"
}

# ── Main ───────────────────────────────────────────────────────────────────────
if [ -f "$GPG_DEST" ]; then
    echo "==> GPG binary sudah ada di $GPG_DEST, skip download"
    file "$GPG_DEST"
    exit 0
fi

if download_from_termux; then
    echo "==> ✓ Berhasil mendapatkan GPG binary"
else
    echo "==> ✗ Download dari Termux gagal"
    use_system_gpg_shim
    echo ""
    echo "⚠ PERHATIAN: Anda perlu menyediakan binary GPG ARM secara manual!"
    echo "  Cara mendapatkannya:"
    echo "  1. Di Termux: cp \$(which gpg) /path/to/repo/app/src/main/assets/gpg"
    echo "  2. Commit dan push file binary tersebut"
    echo "  3. Tambahkan file tersebut ke .gitattributes sebagai binary:"
    echo "     app/src/main/assets/gpg binary"
    echo ""
fi

# Verifikasi
if [ -f "$GPG_DEST" ]; then
    chmod 755 "$GPG_DEST"
    echo "==> Info binary:"
    file "$GPG_DEST" || true
    ls -lh "$GPG_DEST"
    echo "==> ✓ $GPG_DEST siap"
else
    echo "==> ✗ ERROR: GPG binary tidak tersedia!"
    exit 1
fi
