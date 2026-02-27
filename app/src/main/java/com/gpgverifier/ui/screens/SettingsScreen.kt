package com.gpgverifier.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.gpgverifier.keyring.KeyringRepository
import com.gpgverifier.prefs.AppPreferences
import com.gpgverifier.util.AppLogger
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun SettingsScreen(filesDir: File, modifier: Modifier = Modifier) {
    val context     = LocalContext.current
    val scope       = rememberCoroutineScope()
    val scrollState = rememberScrollState()
    val snack       = remember { SnackbarHostState() }
    val repo        = remember { KeyringRepository(context) }

    // Load prefs
    var hashAlgo   by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_HASH_ALGO,   AppPreferences.DEFAULT_HASH_ALGO)) }
    var keyserver  by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_KEYSERVER,   AppPreferences.DEFAULT_KEYSERVER)) }
    var signingKey by remember { mutableStateOf(AppPreferences.get(context, AppPreferences.KEY_SIGNING_KEY_FP, AppPreferences.DEFAULT_SIGNING_KEY)) }

    var hashMenuExpanded by remember { mutableStateOf(false) }
    var keyserverEditing by remember { mutableStateOf(false) }
    var keyserverDraft   by remember { mutableStateOf(keyserver) }
    var logSize          by remember { mutableStateOf(0L) }

    LaunchedEffect(Unit) {
        val logFile = File(filesDir, "logs/app.log")
        logSize = if (logFile.exists()) logFile.length() else 0L
    }

    Scaffold(snackbarHost = { SnackbarHost(snack) }) { innerPad ->
        Column(
            modifier = modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(innerPad)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("Settings", style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface)

            // ── Crypto ──────────────────────────────────────────────────────
            SectionHeader("Cryptography")

            SettingsCard {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Default Hash Algorithm", style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium)
                        Text("Used for signing operations", style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                    }
                    Box {
                        OutlinedButton(onClick = { hashMenuExpanded = true }) {
                            Text(hashAlgo)
                            Icon(Icons.Default.ArrowDropDown, null, modifier = Modifier.size(16.dp))
                        }
                        DropdownMenu(expanded = hashMenuExpanded, onDismissRequest = { hashMenuExpanded = false }) {
                            listOf("SHA256", "SHA384", "SHA512").forEach { algo ->
                                DropdownMenuItem(
                                    text = { Text(algo) },
                                    onClick = {
                                        hashAlgo = algo
                                        AppPreferences.set(context, AppPreferences.KEY_HASH_ALGO, algo)
                                        hashMenuExpanded = false
                                    },
                                    leadingIcon = if (hashAlgo == algo) ({
                                        Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary)
                                    }) else null
                                )
                            }
                        }
                    }
                }
            }

            // ── Keyserver ───────────────────────────────────────────────────
            SectionHeader("Network")

            SettingsCard {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Default Keyserver", style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium)
                    if (keyserverEditing) {
                        OutlinedTextField(
                            value = keyserverDraft,
                            onValueChange = { keyserverDraft = it },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            label = { Text("Keyserver URL") },
                            trailingIcon = {
                                Row {
                                    IconButton(onClick = {
                                        keyserver = keyserverDraft
                                        AppPreferences.set(context, AppPreferences.KEY_KEYSERVER, keyserverDraft)
                                        keyserverEditing = false
                                    }) { Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary) }
                                    IconButton(onClick = {
                                        keyserverDraft = keyserver
                                        keyserverEditing = false
                                    }) { Icon(Icons.Default.Close, null) }
                                }
                            }
                        )
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(keyserver, style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                                modifier = Modifier.weight(1f))
                            IconButton(onClick = { keyserverEditing = true }) {
                                Icon(Icons.Default.Edit, null, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }

            // ── Log Management ──────────────────────────────────────────────
            SectionHeader("Log Management")

            SettingsCard {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("App Log", style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium)
                            Text("${logSize / 1024}KB stored", style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = {
                                scope.launch {
                                    try {
                                        val src = File(filesDir, "logs/app.log")
                                        val dst = File("/sdcard/Download/gpgverifier-app.log")
                                        if (src.exists()) {
                                            src.copyTo(dst, overwrite = true)
                                            AppLogger.i("Log exported to ${dst.absolutePath} (${dst.length()} bytes)")
                                            logSize = src.length()
                                            snack.showSnackbar("✓ Log exported to Downloads")
                                        } else snack.showSnackbar("✗ Log file not found")
                                    } catch (e: Exception) { snack.showSnackbar("✗ ${e.message}") }
                                }
                            }) { Text("Export") }

                            Button(
                                onClick = {
                                    scope.launch {
                                        try {
                                            val logFile = File(filesDir, "logs/app.log")
                                            if (logFile.exists()) { logFile.writeText(""); logSize = 0L }
                                            snack.showSnackbar("✓ Log cleared")
                                        } catch (e: Exception) { snack.showSnackbar("✗ ${e.message}") }
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                            ) { Text("Clear") }
                        }
                    }
                }
            }

            // ── Reset ───────────────────────────────────────────────────────
            SectionHeader("Reset")

            OutlinedButton(
                onClick = {
                    scope.launch {
                        AppPreferences.clear(context)
                        hashAlgo   = AppPreferences.DEFAULT_HASH_ALGO
                        keyserver  = AppPreferences.DEFAULT_KEYSERVER
                        keyserverDraft = AppPreferences.DEFAULT_KEYSERVER
                        signingKey = AppPreferences.DEFAULT_SIGNING_KEY
                        snack.showSnackbar("✓ Settings reset to defaults")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) {
                Icon(Icons.Default.RestartAlt, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Reset All Settings")
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(title,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp, bottom = 2.dp))
}

@Composable
private fun SettingsCard(content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        content()
    }
}
