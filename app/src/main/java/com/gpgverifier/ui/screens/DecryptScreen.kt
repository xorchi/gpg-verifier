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
import com.gpgverifier.model.DecryptResult
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
            Text("Decrypt File", style = MaterialTheme.typography.titleMedium)

            FilePickerCard("Encrypted File (.gpg / .asc)", inputUri, Icons.Default.Lock) {
                filePicker.launch("*/*")
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
                Text("Decrypt", fontWeight = FontWeight.Bold)
            }

            result?.let { res ->
                if (res.success) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer)
                    ) {
                        Column(modifier = Modifier.padding(16.dp),
                               verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.CheckCircle, null,
                                    tint = MaterialTheme.colorScheme.primary)
                                Spacer(Modifier.width(8.dp))
                                Text("Decryption successful", fontWeight = FontWeight.Bold)
                            }
                            Text("Output saved to cache:", style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                            Text(res.outputPath, style = MaterialTheme.typography.bodySmall)
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
                            Text(res.errorMessage ?: "Decrypt gagal",
                                color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                    }
                }
            }
        }
    }
}
