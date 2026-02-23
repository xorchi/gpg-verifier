package com.gpgverifier.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.gpgverifier.keyring.KeyringRepository
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import com.gpgverifier.model.SignMode
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignEncryptScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val repo    = remember { KeyringRepository(context) }
    val scope   = rememberCoroutineScope()
    val scroll  = rememberScrollState()

    // Tabs: Sign | Encrypt
    var tabIndex by remember { mutableIntStateOf(0) }
    val tabs = listOf("Sign", "Encrypt")

    Column(modifier = modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = tabIndex) {
            tabs.forEachIndexed { i, title ->
                Tab(selected = tabIndex == i, onClick = { tabIndex = i }, text = { Text(title) })
            }
        }
        when (tabIndex) {
            0 -> SignTab(repo, scope, scroll)
            1 -> EncryptTab(repo, scope, scroll)
        }
    }
}

// ── Sign Tab ─────────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignTab(repo: KeyringRepository, scope: kotlinx.coroutines.CoroutineScope, scroll: androidx.compose.foundation.ScrollState) {
    val context = LocalContext.current
    var inputUri  by remember { mutableStateOf<Uri?>(null) }
    var secretKeys by remember { mutableStateOf<List<GpgKey>>(emptyList()) }
    var selectedKey by remember { mutableStateOf<GpgKey?>(null) }
    var signMode  by remember { mutableStateOf(SignMode.DETACH_ARMOR) }
    var passphrase by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var resultMsg by remember { mutableStateOf<String?>(null) }
    var outputPath by remember { mutableStateOf<String?>(null) }
    val snackState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) { secretKeys = repo.listSecretKeys() }
    LaunchedEffect(resultMsg) { resultMsg?.let { snackState.showSnackbar(it); resultMsg = null } }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { inputUri = it }

    val modes = listOf(
        SignMode.DETACH_ARMOR  to "Detach (armored .sig.asc)",
        SignMode.DETACH        to "Detach (binary .sig)",
        SignMode.CLEARSIGN     to "Clearsign (.asc)",
        SignMode.NORMAL_ARMOR  to "Embedded (armored .gpg.asc)",
        SignMode.NORMAL        to "Embedded (binary .gpg)"
    )

    Scaffold(snackbarHost = { SnackbarHost(snackState) }) { padding ->
        Column(
            modifier = Modifier
                .padding(padding).padding(16.dp)
                .verticalScroll(scroll),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("Sign File", style = MaterialTheme.typography.titleMedium)

            FilePickerCard("Input File", inputUri, Icons.Default.InsertDriveFile) {
                filePicker.launch("*/*")
            }

            if (secretKeys.isEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text("No secret keys found. Generate or import a key first.",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                }
            } else {
                Text("Signing Key", style = MaterialTheme.typography.labelMedium)
                secretKeys.forEach { key ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = selectedKey == key, onClick = { selectedKey = key })
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(key.uids.firstOrNull() ?: key.keyId, fontWeight = FontWeight.Medium)
                            Text(key.fingerprint.chunked(4).joinToString(" "),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                        }
                    }
                }
            }

            Text("Signature Mode", style = MaterialTheme.typography.labelMedium)
            var modeExpanded by remember { mutableStateOf(false) }
            ExposedDropdownMenuBox(expanded = modeExpanded, onExpandedChange = { modeExpanded = it }) {
                OutlinedTextField(
                    value = modes.first { it.first == signMode }.second,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Mode") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(modeExpanded) },
                    modifier = Modifier.fillMaxWidth().menuAnchor()
                )
                ExposedDropdownMenu(expanded = modeExpanded, onDismissRequest = { modeExpanded = false }) {
                    modes.forEach { (mode, label) ->
                        DropdownMenuItem(text = { Text(label) }, onClick = {
                            signMode = mode; modeExpanded = false
                        })
                    }
                }
            }

            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Button(
                onClick = {
                    val uri = inputUri ?: return@Button
                    val key = selectedKey ?: return@Button
                    scope.launch {
                        isLoading = true; outputPath = null
                        val res = repo.sign(uri, context, key.fingerprint, signMode, passphrase)
                        isLoading = false
                        if (res.success) outputPath = res.outputPath
                        else resultMsg = "✗ ${res.errorMessage}"
                    }
                },
                enabled = inputUri != null && selectedKey != null && !isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) { CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp); Spacer(Modifier.width(8.dp)) }
                Icon(Icons.Default.Lock, null); Spacer(Modifier.width(8.dp))
                Text("Sign", fontWeight = FontWeight.Bold)
            }

            outputPath?.let {
                SuccessCard("Signed file saved to cache:\n$it")
            }
        }
    }
}

// ── Encrypt Tab ───────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EncryptTab(repo: KeyringRepository, scope: kotlinx.coroutines.CoroutineScope, scroll: androidx.compose.foundation.ScrollState) {
    val context = LocalContext.current
    var inputUri   by remember { mutableStateOf<Uri?>(null) }
    var publicKeys by remember { mutableStateOf<List<GpgKey>>(emptyList()) }
    val selected   = remember { mutableStateListOf<String>() }
    var armor      by remember { mutableStateOf(true) }
    var isLoading  by remember { mutableStateOf(false) }
    var resultMsg  by remember { mutableStateOf<String?>(null) }
    var outputPath by remember { mutableStateOf<String?>(null) }
    val snackState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) { publicKeys = repo.listPublicKeys() }
    LaunchedEffect(resultMsg) { resultMsg?.let { snackState.showSnackbar(it); resultMsg = null } }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { inputUri = it }

    Scaffold(snackbarHost = { SnackbarHost(snackState) }) { padding ->
        Column(
            modifier = Modifier
                .padding(padding).padding(16.dp)
                .verticalScroll(scroll),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("Encrypt File", style = MaterialTheme.typography.titleMedium)

            FilePickerCard("Input File", inputUri, Icons.Default.InsertDriveFile) {
                filePicker.launch("*/*")
            }

            if (publicKeys.isEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text("No public keys found. Import recipient keys first.",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                }
            } else {
                Text("Recipients (select one or more)", style = MaterialTheme.typography.labelMedium)
                publicKeys.forEach { key ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Checkbox(
                            checked = selected.contains(key.fingerprint),
                            onCheckedChange = {
                                if (it) selected.add(key.fingerprint)
                                else selected.remove(key.fingerprint)
                            }
                        )
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(key.uids.firstOrNull() ?: key.keyId, fontWeight = FontWeight.Medium)
                            Text(key.fingerprint.chunked(4).joinToString(" "),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                        }
                    }
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = armor, onCheckedChange = { armor = it })
                Spacer(Modifier.width(12.dp))
                Text(if (armor) "Armored output (.asc)" else "Binary output (.gpg)")
            }

            Button(
                onClick = {
                    val uri = inputUri ?: return@Button
                    if (selected.isEmpty()) { resultMsg = "Pilih minimal satu recipient"; return@Button }
                    scope.launch {
                        isLoading = true; outputPath = null
                        val res = repo.encrypt(uri, context, selected.toList(), armor)
                        isLoading = false
                        if (res.success) outputPath = res.outputPath
                        else resultMsg = "✗ ${res.errorMessage}"
                    }
                },
                enabled = inputUri != null && selected.isNotEmpty() && !isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) { CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp); Spacer(Modifier.width(8.dp)) }
                Icon(Icons.Default.Lock, null); Spacer(Modifier.width(8.dp))
                Text("Encrypt", fontWeight = FontWeight.Bold)
            }

            outputPath?.let { SuccessCard("Encrypted file saved to cache:\n$it") }
        }
    }
}

@Composable
fun SuccessCard(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(12.dp))
            Text(message, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
