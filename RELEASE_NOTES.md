GPG Verifier v1.0.0

Initial release.

Features:

Sign
- ClearSign (.asc)
- Detached signature (armored .asc & binary .sig)
- Embedded signature (armored & binary)
- Hash algorithm: SHA-256 / SHA-512

Verify
- ClearSign (.asc)
- Detached signature (armored & binary)
- Embedded signature (armored & binary)

Encrypt
- Asymmetric encryption (armored & binary)
- Symmetric encryption (armored & binary)

Decrypt
- Asymmetric & symmetric

Key Management
- Import public & secret key
- Export / backup public key
- Export / backup all keys (public & private)
- Restore keys from backup
- Keyserver support: search, fetch, upload public key

---

Release Integrity

This release is signed. To verify authenticity:

  APK       : GPG-Verifier.apk
  Signature : GPG-Verifier.apk.asc

Public key is available at:
  - Repository : docs/xorchi-gpg-pubkey.asc
  - Ubuntu Keyserver : https://keyserver.ubuntu.com
    Key ID: 4B495F62CBB37CFF

Verify with:
  gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 4B495F62CBB37CFF
  gpg --verify GPG-Verifier.apk.asc GPG-Verifier.apk
