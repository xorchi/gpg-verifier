package com.gpgverifier.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

fun buildDarkColors(primary: Color) = darkColorScheme(
    primary            = primary,
    onPrimary          = Color(0xFF000000),
    primaryContainer   = primary.copy(alpha = 0.3f),
    secondary          = primary.copy(alpha = 0.7f),
    background         = Color(0xFF0D0D0D),
    surface            = Color(0xFF1A1A1A),
    surfaceVariant     = Color(0xFF2A2A2A),
    error              = Color(0xFFEF5350),
    onBackground       = Color(0xFFE0E0E0),
    onSurface          = Color(0xFFE0E0E0),
    outline            = Color(0xFF444444)
)

fun buildLightColors(primary: Color) = lightColorScheme(
    primary            = primary,
    onPrimary          = Color(0xFFFFFFFF),
    primaryContainer   = primary.copy(alpha = 0.15f),
    secondary          = primary.copy(alpha = 0.7f),
    background         = Color(0xFFF5F5F5),
    surface            = Color(0xFFFFFFFF),
    surfaceVariant     = Color(0xFFEEEEEE),
    error              = Color(0xFFB00020),
    onBackground       = Color(0xFF1A1A1A),
    onSurface          = Color(0xFF1A1A1A),
    outline            = Color(0xFFCCCCCC)
)

@Composable
fun GPGVerifierTheme(
    theme: String  = "dark",
    accent: String = "4CAF50",
    content: @Composable () -> Unit
) {
    val primary = try {
        Color(android.graphics.Color.parseColor("#$accent"))
    } catch (e: Exception) {
        Color(0xFF4CAF50)
    }

    val isDark = when (theme) {
        "light"  -> false
        "dark"   -> true
        else     -> isSystemInDarkTheme()
    }

    val colors = if (isDark) buildDarkColors(primary) else buildLightColors(primary)

    MaterialTheme(colorScheme = colors, content = content)
}
