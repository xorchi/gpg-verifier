package com.gpgverifier.ui.screens

import com.gpgverifier.R

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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.gpgverifier.keyring.KeyringRepository
import com.gpgverifier.model.DecryptResult
import com.gpgverifier.util.FileShareHelper
import kotlinx.coroutines.launch

@Composable
fun DecryptScreen(modifier: Modifier = Modifier) {
    val context    = LocalContext.current
    val repo       = remember { KeyringRepository(context) }
    val scope      = rememberCoroutineScope()
    val scroll     = rememberScrollState()
    val snackState = remember { SnackbarHostState() }

    var inputUri   by remember { mutableStateOf<Uri?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var isLoading  by remember { mutableStateOf(false) }
    var result     by remember { mutableStateOf<DecryptResult?>(null) }
    var snackMsg   by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(snackMsg) { snackMsg?.let { snackState.showSnackbar(it); snackMsg = null } }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { inputUri = it }

    // Launcher for ACTION_CREATE_DOCUMENT (SAF save dialog)
    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { actResult ->
        val destUri = actResult.data?.data ?: return@rememberLauncherForActivityResult
        val srcPath = result?.outputPath ?: return@rememberLauncherForActivityResult
        val ok = FileShareHelper.copyToUri(context, srcPath, destUri)
        snackMsg = if (ok) "✓ File saved successfully" else "✗ Failed to save file"
    }

    Scaffold(
        modifier = modifier,
        snackbarHost = { SnackbarHost(snackState) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding).padding(16.dp)
                .verticalScroll(scroll),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(stringResource(R.string.decrypt_title), style = MaterialTheme.typography.titleMedium)

            FilePickerCard("Encrypted File (.gpg / .asc)", inputUri, Icons.Default.Lock) {
                filePicker.launch("*/*")
            }

            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text(stringResource(R.string.field_passphrase)) },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Button(
                onClick = {
                    val uri = inputUri ?: return@Button
                    scope.launch {
                        isLoading = true; result = null
                        val res = repo.decrypt(uri, context, passphrase)
                        isLoading = false
                        result = res
                        if (!res.success) snackMsg = "✗ ${res.errorMessage}"
                    }
                },
                enabled = inputUri != null && !isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                }
                Icon(Icons.Default.LockOpen, null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.nav_decrypt), fontWeight = FontWeight.Bold)
            }

            result?.let { res ->
                if (res.success) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer)
                    ) {
                        Column(modifier = Modifier.padding(16.dp),
                               verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.CheckCircle, null,
                                    tint = MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.decrypt_success), fontWeight = FontWeight.Bold)
                            }

                            // ── Tombol Save & Share ───────────────────────────
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = {
                                        val intent = FileShareHelper.createSaveIntent(res.outputPath)
                                        saveLauncher.launch(intent)
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Save, null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(stringResource(R.string.action_save))
                                }
                                OutlinedButton(
                                    onClick = { FileShareHelper.shareFile(context, res.outputPath) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Share, null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(stringResource(R.string.action_share))
                                }
                            }

                            Text(stringResource(R.string.cache_path, res.outputPath)),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.45f))
                        }
                    }
                } else {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer)
                    ) {
                        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Cancel, null, tint = MaterialTheme.colorScheme.error)
                            Spacer(Modifier.width(8.dp))
                            Text(res.errorMessage ?: "Decryption failed",
                                color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                    }
                }
            }
        }
    }
}
