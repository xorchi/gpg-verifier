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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gpgverifier.keyring.KeyringRepository
import com.gpgverifier.model.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyringScreen(modifier: Modifier = Modifier) {
    val context   = LocalContext.current
    val repo      = remember { KeyringRepository(context) }
    val scope     = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    var tabIndex  by remember { mutableIntStateOf(0) }
    val tabs       = listOf("Public Keys", "Secret Keys")

    var pubKeys   by remember { mutableStateOf<List<GpgKey>>(emptyList()) }
    var secKeys   by remember { mutableStateOf<List<GpgKey>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var snackMsg  by remember { mutableStateOf<String?>(null) }
    var selectedKey by remember { mutableStateOf<GpgKey?>(null) }
    var showKeyserverImportDialog by remember { mutableStateOf(false) }
    var showKeyserverUploadDialog by remember { mutableStateOf(false) }
    var uploadTargetKey by remember { mutableStateOf<GpgKey?>(null) }
    var showGenDialog   by remember { mutableStateOf(false) }
    val snackState = remember { SnackbarHostState() }

    fun loadKeys() {
        scope.launch {
            isLoading = true
            pubKeys = repo.listPublicKeys()
            secKeys = repo.listSecretKeys()
            isLoading = false
        }
    }

    LaunchedEffect(Unit) { loadKeys() }
    LaunchedEffect(snackMsg) { snackMsg?.let { snackState.showSnackbar(it); snackMsg = null } }

    val keyFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri?.let {
            scope.launch {
                val r = repo.importKeyFromFile(it, context)
                snackMsg = when (r) {
                    is GpgOperationResult.Success -> "✓ ${r.message}"
                    is GpgOperationResult.Failure -> "✗ ${r.error}"
                }
                loadKeys()
            }
        }
    }

    Scaffold(
        modifier = modifier,
        snackbarHost = { SnackbarHost(snackState) },
        floatingActionButton = {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SmallFloatingActionButton(onClick = { showGenDialog = true },
                    containerColor = MaterialTheme.colorScheme.surfaceVariant) {
                    Icon(Icons.Default.VpnKey, "Generate key")
                }
                SmallFloatingActionButton(onClick = { showKeyserverImportDialog = true },
                    containerColor = MaterialTheme.colorScheme.surfaceVariant) {
                    Icon(Icons.Default.CloudDownload, "Import from keyserver")
                }
                FloatingActionButton(onClick = { keyFilePicker.launch("*/*") },
                    containerColor = MaterialTheme.colorScheme.primary) {
                    Icon(Icons.Default.Add, "Import key from file")
                }
            }
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = tabIndex) {
                tabs.forEachIndexed { i, title ->
                    Tab(selected = tabIndex == i, onClick = { tabIndex = i }, text = { Text(title) })
                }
            }
            val keys = if (tabIndex == 0) pubKeys else secKeys
            Box(modifier = Modifier.fillMaxSize()) {
                when {
                    isLoading -> CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
                    keys.isEmpty() -> EmptyKeyringMessage()
                    else -> LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        item {
                            Text("${keys.size} ${if (tabIndex == 0) "public" else "secret"} key(s)",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                                modifier = Modifier.padding(bottom = 4.dp))
                        }
                        items(keys, key = { it.fingerprint }) { key ->
                            KeyCard(
                                key = key,
                                onDelete = {
                                    scope.launch {
                                        val r = repo.deleteKey(key.fingerprint)
                                        snackMsg = when (r) {
                                            is GpgOperationResult.Success -> "Key deleted"
                                            is GpgOperationResult.Failure -> "✗ ${r.error}"
                                        }
                                        loadKeys()
                                    }
                                },
                                onExportPublic = {
                                    scope.launch {
                                        val r = repo.exportKey(key.fingerprint, armor = true, secret = false)
                                        if (r is GpgOperationResult.Success) {
                                            clipboard.setText(AnnotatedString(r.message))
                                            snackMsg = "Public key (armored) copied to clipboard"
                                        } else snackMsg = "✗ Export failed"
                                    }
                                },
                                onExportSecret = if (key.type == KeyType.SECRET) ({
                                    scope.launch {
                                        val r = repo.exportKey(key.fingerprint, armor = true, secret = true)
                                        if (r is GpgOperationResult.Success) {
                                            clipboard.setText(AnnotatedString(r.message))
                                            snackMsg = "Secret key (armored) copied to clipboard"
                                        } else snackMsg = "✗ Export failed"
                                    }
                                }) else null,
                                onUploadToKeyserver = {
                                    uploadTargetKey = key
                                    showKeyserverUploadDialog = true
                                },
                                onBackupPublic = {
                                    scope.launch {
                                        val r = repo.backupPublicKey(key.fingerprint)
                                        snackMsg = when (r) {
                                            is GpgOperationResult.Success -> "✓ ${r.message}"
                                            is GpgOperationResult.Failure -> "✗ ${r.error}"
                                        }
                                    }
                                },
                                onBackupSecret = if (key.type == KeyType.SECRET) ({
                                    scope.launch {
                                        val r = repo.backupSecretKey(key.fingerprint)
                                        snackMsg = when (r) {
                                            is GpgOperationResult.Success -> "✓ ${r.message}"
                                            is GpgOperationResult.Failure -> "✗ ${r.error}"
                                        }
                                    }
                                }) else null,
                                onTrust = { selectedKey = key },
                                onCopyFingerprint = {
                                    clipboard.setText(AnnotatedString(key.fingerprint))
                                    scope.launch { snackMsg = "✓ Fingerprint disalin ke clipboard" }
                                }
                            )
                        }
                        item {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    val r = repo.backupAllPublicKeys()
                                    snackMsg = when (r) {
                                        is GpgOperationResult.Success -> "✓ ${r.message}"
                                        is GpgOperationResult.Failure -> "✗ ${r.error}"
                                    }
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) { Text("Backup All Pub", fontSize = 12.sp) }
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    val r = repo.backupAllSecretKeys()
                                    snackMsg = when (r) {
                                        is GpgOperationResult.Success -> "✓ ${r.message}"
                                        is GpgOperationResult.Failure -> "✗ ${r.error}"
                                    }
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) { Text("Backup All Priv", fontSize = 12.sp) }
                    }
                }
        item { Spacer(Modifier.height(120.dp)) }
                    }
                }
            }
        }
    }

    // Dialog import dari keyserver
    if (showKeyserverImportDialog) {
        KeyserverImportDialog(onDismiss = { showKeyserverImportDialog = false }) { keyId, ks ->
            showKeyserverImportDialog = false
            scope.launch {
                isLoading = true
                val r = repo.importKeyFromKeyserver(keyId, ks)
                snackMsg = when (r) {
                    is GpgOperationResult.Success -> "✓ ${r.message}"
                    is GpgOperationResult.Failure -> "✗ ${r.error}"
                }
                loadKeys(); isLoading = false
            }
        }
    }

    // Dialog upload ke keyserver
    if (showKeyserverUploadDialog && uploadTargetKey != null) {
        KeyserverUploadDialog(
            key = uploadTargetKey!!,
            onDismiss = { showKeyserverUploadDialog = false; uploadTargetKey = null }
        ) { ks ->
            showKeyserverUploadDialog = false
            val key = uploadTargetKey!!
            uploadTargetKey = null
            scope.launch {
                isLoading = true
                val r = repo.exportKeyToKeyserver(key.fingerprint, ks)
                snackMsg = when (r) {
                    is GpgOperationResult.Success -> "✓ ${r.message}"
                    is GpgOperationResult.Failure -> "✗ ${r.error}"
                }
                isLoading = false
            }
        }
    }

    if (showGenDialog) {
        GenerateKeyDialog(onDismiss = { showGenDialog = false }) { params ->
            showGenDialog = false
            scope.launch {
                isLoading = true
                val r = repo.generateKey(params)
                snackMsg = when (r) {
                    is GpgOperationResult.Success -> "✓ ${r.message}"
                    is GpgOperationResult.Failure -> "✗ ${r.error}"
                }
                loadKeys(); isLoading = false
            }
        }
    }

    selectedKey?.let { key ->
        TrustDialog(key = key, onDismiss = { selectedKey = null }) { level ->
            selectedKey = null
            scope.launch {
                val r = repo.trustKey(key.fingerprint, level)
                snackMsg = when (r) {
                    is GpgOperationResult.Success -> "✓ Trust level updated"
                    is GpgOperationResult.Failure -> "✗ ${r.error}"
                }
                loadKeys()
            }
        }
    }
}

// ── Key Card ─────────────────────────────────────────────────────────────────

@Composable
fun KeyCard(
    key: GpgKey,
    onDelete: () -> Unit,
    onExportPublic: () -> Unit,
    onBackupPublic: () -> Unit,
    onBackupSecret: (() -> Unit)?,
    onExportSecret: (() -> Unit)?,
    onUploadToKeyserver: () -> Unit,
    onTrust: () -> Unit,
    onCopyFingerprint: () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }

    val trustColor = when (key.trustLevel) {
        "Full", "Ultimate" -> MaterialTheme.colorScheme.primary
        "Marginal"         -> MaterialTheme.colorScheme.tertiary
        else               -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
    }

    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(if (key.type == KeyType.SECRET) Icons.Default.VpnKey else Icons.Default.Key,
                    null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(key.uids.firstOrNull() ?: key.keyId,
                        fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("0x${key.keyId}", style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                }
                AssistChip(onClick = {}, label = { Text(key.trustLevel, fontSize = 10.sp) },
                    colors = AssistChipDefaults.assistChipColors(labelColor = trustColor))
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore, null)
                }
            }

            if (expanded) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        key.fingerprint.chunked(4).joinToString(" "),
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = onCopyFingerprint, modifier = Modifier.size(32.dp)) {
                        Icon(
                            Icons.Default.ContentCopy, contentDescription = "Copy Fingerprint",
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                if (key.uids.size > 1) {
                    Spacer(Modifier.height(4.dp))
                    key.uids.drop(1).forEach { uid ->
                        Text(uid, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onTrust, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Default.Shield, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp)); Text("Trust")
                    }
                    OutlinedButton(onClick = onExportPublic, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Default.Share, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp)); Text("Export Pub")
                    }
                    OutlinedButton(onClick = onBackupPublic, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Default.Save, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp)); Text("Export Pub")
                    }
                    if (onBackupSecret != null) {
                        OutlinedButton(onClick = onBackupSecret, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Default.Lock, null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp)); Text("Export Priv")
                        }
                    }
                }
                Spacer(Modifier.height(4.dp))
                // Tombol upload ke keyserver
                OutlinedButton(onClick = onUploadToKeyserver, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.CloudUpload, null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp)); Text("Upload ke Keyserver")
                }
                if (onExportSecret != null) {
                    Spacer(Modifier.height(4.dp))
                    OutlinedButton(onClick = onExportSecret, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.Warning, null, modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.error)
                        Spacer(Modifier.width(4.dp))
                        Text("Export Secret Key", color = MaterialTheme.colorScheme.error)
                    }
                }
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = { showDeleteConfirm = true },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Delete, null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp)); Text("Delete Key")
                }
            }
        }
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Delete Key?") },
            text  = { Text("This will permanently remove the key from your keyring.") },
            confirmButton = {
                TextButton(onClick = { showDeleteConfirm = false; onDelete() },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { showDeleteConfirm = false }) { Text("Cancel") } }
        )
    }
}

// ── Dialogs ───────────────────────────────────────────────────────────────────

@Composable
fun KeyserverImportDialog(onDismiss: () -> Unit, onImport: (String, String) -> Unit) {
    var keyId     by remember { mutableStateOf("") }
    var keyserver by remember { mutableStateOf("hkps://keyserver.ubuntu.com") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Import from Keyserver") },
        text  = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(value = keyId, onValueChange = { keyId = it },
                    label = { Text("Key ID or Fingerprint") },
                    placeholder = { Text("e.g. 0xABCDEF12") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = keyserver, onValueChange = { keyserver = it },
                    label = { Text("Keyserver") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { if (keyId.isNotBlank()) onImport(keyId.trim(), keyserver.trim()) },
                enabled = keyId.isNotBlank()) { Text("Import") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
fun KeyserverUploadDialog(key: GpgKey, onDismiss: () -> Unit, onUpload: (String) -> Unit) {
    var keyserver by remember { mutableStateOf("hkps://keyserver.ubuntu.com") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Upload ke Keyserver") },
        text  = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Key: ${key.uids.firstOrNull() ?: key.keyId}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                OutlinedTextField(value = keyserver, onValueChange = { keyserver = it },
                    label = { Text("Keyserver") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { onUpload(keyserver.trim()) }) { Text("Upload") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

fun isPasswordStrong(p: String): Boolean {
    if (p.length < 6) return false
    if (!p.any { it.isLowerCase() }) return false
    if (!p.any { it.isUpperCase() }) return false
    if (!p.any { it.isDigit() }) return false
    if (!p.any { !it.isLetterOrDigit() }) return false
    return true
}

fun passwordHint(p: String): String {
    if (p.isEmpty()) return "Minimal 6 karakter: huruf besar, kecil, angka, dan simbol"
    val missing = mutableListOf<String>()
    if (!p.any { it.isLowerCase() }) missing.add("huruf kecil")
    if (!p.any { it.isUpperCase() }) missing.add("huruf besar")
    if (!p.any { it.isDigit() }) missing.add("angka")
    if (!p.any { !it.isLetterOrDigit() }) missing.add("simbol")
    if (p.length < 6) missing.add("minimal 6 karakter")
    return if (missing.isEmpty()) "" else "Diperlukan: ${missing.joinToString(", ")}"
}

@Composable
fun GenerateKeyDialog(onDismiss: () -> Unit, onGenerate: (KeyGenParams) -> Unit) {
    var name       by remember { mutableStateOf("") }
    var email      by remember { mutableStateOf("") }
    var comment    by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var confirm    by remember { mutableStateOf("") }
    var keySize    by remember { mutableStateOf("4096") }
    var expiry     by remember { mutableStateOf("0") }

    val passStrong   = isPasswordStrong(passphrase)
    val passMatch    = passphrase == confirm && confirm.isNotEmpty()
    val passHint     = passwordHint(passphrase)
    val canGenerate  = name.isNotBlank() && email.isNotBlank() && passStrong && passMatch

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generate Key Pair") },
        text  = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(value = name, onValueChange = { name = it },
                    label = { Text("Name *") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = email, onValueChange = { email = it },
                    label = { Text("Email *") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = comment, onValueChange = { comment = it },
                    label = { Text("Comment (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    value = passphrase, onValueChange = { passphrase = it },
                    label = { Text("Passphrase *") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    isError = passphrase.isNotEmpty() && !passStrong,
                    supportingText = {
                        if (passphrase.isNotEmpty() && !passStrong)
                            Text(passHint, color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.labelSmall)
                        else if (passphrase.isEmpty())
                            Text("Wajib diisi", color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.labelSmall)
                    }
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text("Konfirmasi Passphrase *") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    isError = confirm.isNotEmpty() && !passMatch,
                    supportingText = {
                        if (confirm.isNotEmpty() && !passMatch)
                            Text("Passphrase tidak cocok", color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.labelSmall)
                    }
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(value = keySize, onValueChange = { keySize = it },
                        label = { Text("Key Size") }, singleLine = true, modifier = Modifier.weight(1f))
                    OutlinedTextField(value = expiry, onValueChange = { expiry = it },
                        label = { Text("Expiry (days, 0=never)") }, singleLine = true, modifier = Modifier.weight(1f))
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (canGenerate) {
                        onGenerate(KeyGenParams(
                            name       = name.trim(),
                            email      = email.trim(),
                            comment    = comment.trim(),
                            keySize    = keySize.toIntOrNull() ?: 4096,
                            expiry     = expiry.toIntOrNull() ?: 0,
                            passphrase = passphrase
                        ))
                    }
                },
                enabled = canGenerate
            ) { Text("Generate") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
fun TrustDialog(key: GpgKey, onDismiss: () -> Unit, onSetTrust: (Int) -> Unit) {
    val trustOptions = listOf(1 to "Unknown", 2 to "None", 3 to "Marginal", 4 to "Full", 5 to "Ultimate")
    var selected by remember { mutableIntStateOf(3) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set Trust Level") },
        text  = {
            Column {
                Text(key.uids.firstOrNull() ?: key.keyId,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                Spacer(Modifier.height(12.dp))
                trustOptions.forEach { (level, label) ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                        RadioButton(selected = selected == level, onClick = { selected = level })
                        Text(label, modifier = Modifier.padding(start = 4.dp))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onSetTrust(selected) }) { Text("Apply") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
fun EmptyKeyringMessage() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Default.Key, null, modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f))
            Text("No keys found", style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
            Text("Import or generate a key to get started",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f))
        }
    }
}
