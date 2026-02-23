package com.gpgverifier.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4CAF50),
    onPrimary = Color(0xFF000000),
    primaryContainer = Color(0xFF1B5E20),
    secondary = Color(0xFF81C784),
    background = Color(0xFF0D0D0D),
    surface = Color(0xFF1A1A1A),
    surfaceVariant = Color(0xFF2A2A2A),
    error = Color(0xFFEF5350),
    onBackground = Color(0xFFE0E0E0),
    onSurface = Color(0xFFE0E0E0),
    outline = Color(0xFF444444)
)

@Composable
fun GPGVerifierTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColors,
        content = content
    )
}
