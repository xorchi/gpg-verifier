package com.gpgverifier.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gpgverifier.keyring.KeyringRepository
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyringScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val repo = remember { KeyringRepository(context) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    var keys by remember { mutableStateOf<List<GpgKey>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var snackbarMessage by remember { mutableStateOf<String?>(null) }
    var showImportDialog by remember { mutableStateOf(false) }
    var showKeyserverDialog by remember { mutableStateOf(false) }
    var selectedKey by remember { mutableStateOf<GpgKey?>(null) }
    val snackbarState = remember { SnackbarHostState() }

    fun loadKeys() {
        scope.launch {
            isLoading = true
            keys = repo.listPublicKeys()
            isLoading = false
        }
    }

    LaunchedEffect(Unit) { loadKeys() }

    LaunchedEffect(snackbarMessage) {
        snackbarMessage?.let {
            snackbarState.showSnackbar(it)
            snackbarMessage = null
        }
    }

    val keyFilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            scope.launch {
                val result = repo.importKeyFromFile(it, context)
                snackbarMessage = when (result) {
                    is GpgOperationResult.Success -> "✓ ${result.message}"
                    is GpgOperationResult.Failure -> "✗ ${result.error}"
                }
                loadKeys()
            }
        }
    }

    Scaffold(
        modifier = modifier,
        snackbarHost = { SnackbarHost(snackbarState) },
        floatingActionButton = {
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                SmallFloatingActionButton(
                    onClick = { showKeyserverDialog = true },
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ) {
                    Icon(Icons.Default.CloudDownload, contentDescription = "Import from keyserver")
                }
                FloatingActionButton(
                    onClick = { keyFilePicker.launch("*/*") },
                    containerColor = MaterialTheme.colorScheme.primary
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Import key from file")
                }
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when {
                isLoading -> CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
                keys.isEmpty() -> EmptyKeyringMessage()
                else -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        item {
                            Text(
                                "${keys.size} public key(s)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                                modifier = Modifier.padding(bottom = 4.dp)
                            )
                        }
                        items(keys, key = { it.fingerprint }) { key ->
                            KeyCard(
                                key = key,
                                onDelete = {
                                    scope.launch {
                                        val result = repo.deleteKey(key.fingerprint)
                                        snackbarMessage = when (result) {
                                            is GpgOperationResult.Success -> "Key deleted"
                                            is GpgOperationResult.Failure -> "✗ ${result.error}"
                                        }
                                        loadKeys()
                                    }
                                },
                                onExport = {
                                    scope.launch {
                                        val result = repo.exportKey(key.fingerprint)
                                        if (result is GpgOperationResult.Success) {
                                            clipboard.setText(AnnotatedString(result.message))
                                            snackbarMessage = "Armored key copied to clipboard"
                                        } else {
                                            snackbarMessage = "✗ Export failed"
                                        }
                                    }
                                },
                                onTrust = { selectedKey = key }
                            )
                        }
                        item { Spacer(Modifier.height(80.dp)) }
                    }
                }
            }
        }
    }

    // Keyserver import dialog
    if (showKeyserverDialog) {
        KeyserverImportDialog(
            onDismiss = { showKeyserverDialog = false },
            onImport = { keyId, keyserver ->
                showKeyserverDialog = false
                scope.launch {
                    isLoading = true
                    val result = repo.importKeyFromKeyserver(keyId, keyserver)
                    snackbarMessage = when (result) {
                        is GpgOperationResult.Success -> "✓ ${result.message}"
                        is GpgOperationResult.Failure -> "✗ ${result.error}"
                    }
                    loadKeys()
                    isLoading = false
                }
            }
        )
    }

    // Trust level dialog
    selectedKey?.let { key ->
        TrustDialog(
            key = key,
            onDismiss = { selectedKey = null },
            onSetTrust = { level ->
                selectedKey = null
                scope.launch {
                    val result = repo.trustKey(key.fingerprint, level)
                    snackbarMessage = when (result) {
                        is GpgOperationResult.Success -> "✓ Trust level updated"
                        is GpgOperationResult.Failure -> "✗ ${result.error}"
                    }
                    loadKeys()
                }
            }
        )
    }
}

@Composable
fun KeyCard(
    key: GpgKey,
    onDelete: () -> Unit,
    onExport: () -> Unit,
    onTrust: () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }

    val trustColor = when (key.trustLevel) {
        "Ultimate", "Full" -> MaterialTheme.colorScheme.primary
        "Marginal" -> MaterialTheme.colorScheme.tertiary
        "Revoked", "Expired" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    Icons.Default.Key,
                    contentDescription = null,
                    tint = trustColor,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        key.uids.firstOrNull() ?: "Unknown UID",
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        key.keyId.takeLast(8).uppercase(),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                    )
                }
                AssistChip(
                    onClick = {},
                    label = { Text(key.trustLevel, fontSize = 11.sp) },
                    colors = AssistChipDefaults.assistChipColors(
                        labelColor = trustColor
                    )
                )
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = null
                    )
                }
            }

            if (expanded) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                // UID list
                if (key.uids.size > 1) {
                    key.uids.drop(1).forEach { uid ->
                        Text(
                            uid,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                }

                // Fingerprint
                Text(
                    "Fingerprint",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                )
                Text(
                    key.fingerprint.chunked(4).joinToString(" "),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(4.dp))

                // Dates
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Column {
                        Text("Created", style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                        Text(key.createdAt, style = MaterialTheme.typography.bodySmall)
                    }
                    key.expiresAt?.let {
                        Column {
                            Text("Expires", style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                            Text(it, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onTrust) {
                        Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Trust")
                    }
                    TextButton(onClick = onExport) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Export")
                    }
                    TextButton(
                        onClick = { showDeleteConfirm = true },
                        colors = ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Delete")
                    }
                }
            }
        }
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Delete Key?") },
            text = { Text("This will permanently remove the key from your keyring.") },
            confirmButton = {
                TextButton(
                    onClick = { showDeleteConfirm = false; onDelete() },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
fun KeyserverImportDialog(onDismiss: () -> Unit, onImport: (String, String) -> Unit) {
    var keyId by remember { mutableStateOf("") }
    var keyserver by remember { mutableStateOf("hkps://keys.openpgp.org") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Import from Keyserver") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = keyId,
                    onValueChange = { keyId = it },
                    label = { Text("Key ID or Fingerprint") },
                    placeholder = { Text("e.g. 0xABCDEF12") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = keyserver,
                    onValueChange = { keyserver = it },
                    label = { Text("Keyserver") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { if (keyId.isNotBlank()) onImport(keyId.trim(), keyserver.trim()) },
                enabled = keyId.isNotBlank()
            ) { Text("Import") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
fun TrustDialog(key: GpgKey, onDismiss: () -> Unit, onSetTrust: (Int) -> Unit) {
    val trustOptions = listOf(
        1 to "Unknown",
        2 to "None",
        3 to "Marginal",
        4 to "Full",
        5 to "Ultimate"
    )
    var selected by remember { mutableStateOf(3) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set Trust Level") },
        text = {
            Column {
                Text(
                    key.uids.firstOrNull() ?: key.keyId,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                )
                Spacer(Modifier.height(12.dp))
                trustOptions.forEach { (level, label) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        RadioButton(selected = selected == level, onClick = { selected = level })
                        Text(label, modifier = Modifier.padding(start = 4.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSetTrust(selected) }) { Text("Apply") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
fun EmptyKeyringMessage() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(
                Icons.Default.Key,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f)
            )
            Text(
                "No keys in keyring",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
            )
            Text(
                "Tap + to import a key",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f)
            )
        }
    }
}
