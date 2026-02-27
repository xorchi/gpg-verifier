package com.gpgverifier.ui.screens

import com.gpgverifier.R

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gpgverifier.keyring.KeyringRepository
import com.gpgverifier.model.VerificationResult
import kotlinx.coroutines.launch

@Composable
fun VerifyScreen(modifier: Modifier = Modifier) {
    val context     = LocalContext.current
    val repo        = remember { KeyringRepository(context) }
    val scope       = rememberCoroutineScope()
    val scrollState = rememberScrollState()

    // Mode: 0=detached, 1=clearsign, 2=embedded
    var verifyMode by remember { mutableStateOf(0) }

    var dataUri       by remember { mutableStateOf<Uri?>(null) }
    var sigUri        by remember { mutableStateOf<Uri?>(null) }
    var clearSignUri  by remember { mutableStateOf<Uri?>(null) }
    var embeddedUri   by remember { mutableStateOf<Uri?>(null) }
    var result        by remember { mutableStateOf<VerificationResult?>(null) }
    var isLoading     by remember { mutableStateOf(false) }
    var showRawOutput by remember { mutableStateOf(false) }

    val dataFilePicker     = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { dataUri = it }
    val sigFilePicker      = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { sigUri = it }
    val embeddedFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { embeddedUri = it }
    val clearSignFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { clearSignUri = it }

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(scrollState).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(stringResource(R.string.verify_button), style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface)

        // ── Toggle Mode ──────────────────────────────────────────────────────
        Card(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.padding(16.dp).fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        when (verifyMode) {
                            1 -> "Mode: ClearSign"
                            2 -> "Mode: Embedded"
                            else -> "Mode: Detached Signature"
                        },
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        when (verifyMode) {
                            1 -> "Single .asc file containing text + signature"
                            2 -> "Embedded .gpg/.asc file with data + signature"
                            else -> "Separate data file + signature file"
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    )
                }
                Switch(
                    checked = verifyMode == 1,
                    onCheckedChange = {
                        verifyMode = if (it) 1 else 0
                        result = null
                        dataUri = null
                        sigUri = null
                        clearSignUri = null
                    }
                )
            }
        }

        // ── File Picker berdasarkan mode ─────────────────────────────────────
        // Tombol mode Embedded
        Row(modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
            TextButton(onClick = { verifyMode = if (verifyMode == 2) 0 else 2 }) {
                Text(if (verifyMode == 2) "← Back to Detached" else "Switch to Embedded mode",
                    style = MaterialTheme.typography.labelMedium)
            }
        }

        if (verifyMode == 1) {
            FilePickerCard("ClearSign File (.asc)", clearSignUri, Icons.Default.VerifiedUser) {
                clearSignFilePicker.launch("*/*")
            }
        } else if (verifyMode == 2) {
            FilePickerCard("Embedded Signed File (.gpg / .asc)", embeddedUri, Icons.Default.VerifiedUser) {
                embeddedFilePicker.launch("*/*")
            }
        } else {
            FilePickerCard("File to Verify", dataUri, Icons.AutoMirrored.Filled.InsertDriveFile) {
                dataFilePicker.launch("*/*")
            }
            FilePickerCard("Signature File (.sig / .asc)", sigUri, Icons.Default.VerifiedUser) {
                sigFilePicker.launch("*/*")
            }
        }

        // ── Tombol Verify ────────────────────────────────────────────────────
        Button(
            onClick = {
                scope.launch {
                    isLoading = true; result = null
                    result = when (verifyMode) {
                        1 -> {
                            val cs = clearSignUri ?: return@launch
                            repo.verifyClearSign(cs, context)
                        }
                        2 -> {
                            val em = embeddedUri ?: return@launch
                            repo.verifyEmbedded(em, context)
                        }
                        else -> {
                            val d = dataUri ?: return@launch
                            val s = sigUri  ?: return@launch
                            repo.verify(d, s, context)
                        }
                    }
                    isLoading = false
                }
            },
            enabled = when (verifyMode) {
                1 -> clearSignUri != null && !isLoading
                2 -> embeddedUri != null && !isLoading
                else -> dataUri != null && sigUri != null && !isLoading
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
        ) {
            if (isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp)); Text(stringResource(R.string.verifying))
            } else {
                Icon(Icons.Default.Shield, null); Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.verify_button), fontWeight = FontWeight.Bold)
            }
        }

        AnimatedVisibility(visible = result != null, enter = fadeIn(), exit = fadeOut()) {
            result?.let { VerificationResultCard(it, showRawOutput) { showRawOutput = !showRawOutput } }
        }
    }
}

@Composable
fun FilePickerCard(
    label: String,
    uri: Uri?,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    OutlinedCard(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        border = CardDefaults.outlinedCardBorder().copy(width = if (uri != null) 1.5.dp else 1.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(icon, null,
                tint = if (uri != null) MaterialTheme.colorScheme.primary
                       else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
            Column(modifier = Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                Text(
                    uri?.lastPathSegment ?: "Tap to select",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (uri != null) MaterialTheme.colorScheme.onSurface
                            else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
                )
            }
            if (uri != null) Icon(Icons.Default.CheckCircle, null,
                tint = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
fun VerificationResultCard(
    result: VerificationResult,
    showRawOutput: Boolean,
    onToggleRaw: () -> Unit
) {
    val isValid = result.isValid
    val containerColor = if (isValid)
        MaterialTheme.colorScheme.primaryContainer
    else
        MaterialTheme.colorScheme.errorContainer

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (isValid) Icons.Default.CheckCircle else Icons.Default.Cancel,
                    contentDescription = null,
                    tint = if (isValid) MaterialTheme.colorScheme.primary
                           else MaterialTheme.colorScheme.error
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    if (isValid) "Signature Valid" else "Signature Invalid",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = if (isValid) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.error
                )
            }

            if (result.errorMessage != null) {
                Text(result.errorMessage, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error)
            }

            if (result.signedBy.isNotBlank()) {
                Divider(modifier = Modifier.padding(vertical = 4.dp))
                InfoRow("Signed by", result.signedBy)
                InfoRow("Fingerprint", result.fingerprint.chunked(4).joinToString(" "))
                if (result.hashAlgorithm.isNotBlank())
                    InfoRow("Hash Algorithm", result.hashAlgorithm)
                InfoRow("Timestamp", result.timestamp)
                InfoRow("Trust Level", result.trustLevel)
            }

            TextButton(onClick = onToggleRaw) {
                Text(if (showRawOutput) "Hide Raw Output" else "Show Raw Output")
            }

            if (showRawOutput) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(8.dp))
                        .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        result.rawOutput,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

