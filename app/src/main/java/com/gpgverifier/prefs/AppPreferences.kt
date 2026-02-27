package com.gpgverifier.prefs

import android.content.Context
import androidx.core.content.edit

object AppPreferences {

    private const val PREF_FILE = "gpgverifier_prefs"

    // Appearance
    const val KEY_THEME        = "theme"          // "dark" | "light" | "system"
    const val KEY_ACCENT_COLOR = "accent_color"   // hex string e.g. "4CAF50"
    const val KEY_FONT_SIZE    = "font_size"       // "small" | "medium" | "large"
    const val KEY_LAYOUT       = "layout"          // "compact" | "comfortable"

    // Settings
    const val KEY_HASH_ALGO       = "default_hash"      // "SHA256" | "SHA512" | "SHA384"
    const val KEY_KEYSERVER       = "default_keyserver" // url string
    const val KEY_SIGNING_KEY_FP  = "default_signing_key_fp"

    // Defaults
    const val DEFAULT_THEME        = "system"
    const val DEFAULT_ACCENT_COLOR = "4CAF50"
    const val DEFAULT_FONT_SIZE    = "medium"
    const val DEFAULT_LAYOUT       = "comfortable"
    const val DEFAULT_HASH_ALGO    = "SHA512"
    const val DEFAULT_KEYSERVER    = "hkps://keyserver.ubuntu.com"
    const val DEFAULT_SIGNING_KEY  = ""

    fun get(context: Context, key: String, default: String = ""): String =
        context.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
            .getString(key, default) ?: default

    fun set(context: Context, key: String, value: String) =
        context.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
            .edit { putString(key, value) }

    fun clear(context: Context) =
        context.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE).edit { clear() }
}
