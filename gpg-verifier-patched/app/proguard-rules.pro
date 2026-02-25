-keep class com.gpgverifier.** { *; }
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable

# BouncyCastle — wajib agar type checking internal BC tidak gagal setelah R8 obfuscation
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
