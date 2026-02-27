package com.gpgverifier.ui.screens

import com.gpgverifier.R

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Language
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.material3.*
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gpgverifier.prefs.AppPreferences

val ACCENT_COLORS = listOf(
    "4CAF50" to "Green",
    "2196F3" to "Blue",
    "9C27B0" to "Purple",
    "FF9800" to "Orange",
    "F44336" to "Red",
    "00BCD4" to "Cyan",
    "FFEB3B" to "Yellow",
    "E91E63" to "Pink",
)

@Composable
fun AppearanceScreen(
    onThemeChange: (String) -> Unit,
    onAccentChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val context     = LocalContext.current
    val scrollState = rememberScrollState()

    var theme   by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_THEME,   AppPreferences.DEFAULT_THEME)) }
    var accent  by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_ACCENT_COLOR, AppPreferences.DEFAULT_ACCENT_COLOR)) }
    var fontSize by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_FONT_SIZE, AppPreferences.DEFAULT_FONT_SIZE)) }
    var layout  by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_LAYOUT,  AppPreferences.DEFAULT_LAYOUT)) }

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(scrollState).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(stringResource(R.string.nav_appearance), style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface)

        // ── Language ────────────────────────────────────────────────────────
        SectionHeader("Language")
        Card(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.padding(16.dp).fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("App Language", style = MaterialTheme.typography.bodyMedium,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.Medium)
                    Text("Opens system language settings",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                }
                OutlinedButton(onClick = {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        context.startActivity(
                            Intent(Settings.ACTION_APP_LOCALE_SETTINGS).apply {
                                data = Uri.parse("package:${context.packageName}")
                            }
                        )
                    } else {
                        context.startActivity(Intent(Settings.ACTION_LOCALE_SETTINGS))
                    }
                }) {
                    Icon(Icons.Default.Language, null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Change")
                }
            }
        }

        // ── Theme ────────────────────────────────────────────────────────────
        SectionHeader("Theme")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("system" to "System Default", "dark" to "Dark", "light" to "Light").forEach { (key, label) ->
                    Row(
                        modifier = Modifier.fillMaxWidth().clickable {
                            theme = key
                            AppPreferences.set(context, AppPreferences.KEY_THEME, key)
                            onThemeChange(key)
                        }.padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(label, style = MaterialTheme.typography.bodyMedium)
                        RadioButton(selected = theme == key, onClick = {
                            theme = key
                            AppPreferences.set(context, AppPreferences.KEY_THEME, key)
                            onThemeChange(key)
                        })
                    }
                }
            }
        }

        // ── Accent Color ─────────────────────────────────────────────────────
        SectionHeader("Accent Color")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(horizontal = 4.dp)
                ) {
                    items(ACCENT_COLORS) { (hex, name) ->
                        val color = Color(android.graphics.Color.parseColor("#$hex"))
                        val isSelected = accent == hex
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .clip(CircleShape)
                                .background(color)
                                .then(if (isSelected) Modifier.border(3.dp, MaterialTheme.colorScheme.onSurface, CircleShape) else Modifier)
                                .clickable {
                                    accent = hex
                                    AppPreferences.set(context, AppPreferences.KEY_ACCENT_COLOR, hex)
                                    onAccentChange(hex)
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            if (isSelected) Icon(Icons.Default.Check, null,
                                tint = if (hex == "FFEB3B") Color.Black else Color.White,
                                modifier = Modifier.size(22.dp))
                        }
                    }
                }
                Text(
                    ACCENT_COLORS.firstOrNull { it.first == accent }?.second ?: accent,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    modifier = Modifier.align(Alignment.CenterHorizontally)
                )
            }
        }

        // ── Font Size ────────────────────────────────────────────────────────
        SectionHeader("Font Size")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("small" to "Small", "medium" to "Medium", "large" to "Large").forEach { (key, label) ->
                    Row(
                        modifier = Modifier.fillMaxWidth().clickable {
                            fontSize = key
                            AppPreferences.set(context, AppPreferences.KEY_FONT_SIZE, key)
                        }.padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(label,
                            style = MaterialTheme.typography.bodyMedium,
                            fontSize = when(key) { "small" -> 13.sp; "large" -> 17.sp; else -> 15.sp })
                        RadioButton(selected = fontSize == key, onClick = {
                            fontSize = key
                            AppPreferences.set(context, AppPreferences.KEY_FONT_SIZE, key)
                        })
                    }
                }
            }
        }

        // ── Layout ───────────────────────────────────────────────────────────
        SectionHeader("Layout Density")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("compact" to "Compact", "comfortable" to "Comfortable").forEach { (key, label) ->
                    Row(
                        modifier = Modifier.fillMaxWidth().clickable {
                            layout = key
                            AppPreferences.set(context, AppPreferences.KEY_LAYOUT, key)
                        }.padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(label, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                if (key == "compact") "Denser UI, more content visible"
                                else "More spacing, easier to tap",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                            )
                        }
                        RadioButton(selected = layout == key, onClick = {
                            layout = key
                            AppPreferences.set(context, AppPreferences.KEY_LAYOUT, key)
                        })
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = {
                    AppPreferences.set(context, AppPreferences.KEY_THEME, AppPreferences.DEFAULT_THEME)
                    AppPreferences.set(context, AppPreferences.KEY_ACCENT_COLOR, AppPreferences.DEFAULT_ACCENT_COLOR)
                    AppPreferences.set(context, AppPreferences.KEY_FONT_SIZE, AppPreferences.DEFAULT_FONT_SIZE)
                    AppPreferences.set(context, AppPreferences.KEY_LAYOUT, AppPreferences.DEFAULT_LAYOUT)
                    onThemeChange(AppPreferences.DEFAULT_THEME)
                    onAccentChange(AppPreferences.DEFAULT_ACCENT_COLOR)
                },
                modifier = Modifier.weight(1f)
            ) { Text(stringResource(R.string.action_cancel)) }
            Button(
                onClick = { /* prefs sudah disimpan real-time saat user memilih */ },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
            ) {
                Icon(Icons.Default.Check, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.action_apply))
            }
        }
    }
}
