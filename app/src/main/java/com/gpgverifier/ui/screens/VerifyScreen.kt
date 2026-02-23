package com.gpgverifier.ui.screens

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
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifyScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val repo = remember { KeyringRepository(context) }
    val scope = rememberCoroutineScope()
    val scrollState = rememberScrollState()

    var dataUri by remember { mutableStateOf<Uri?>(null) }
    var sigUri by remember { mutableStateOf<Uri?>(null) }
    var result by remember { mutableStateOf<VerificationResult?>(null) }
    var isLoading by remember { mutableStateOf(false) }
    var showRawOutput by remember { mutableStateOf(false) }

    val dataFilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri -> dataUri = uri }

    val sigFilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri -> sigUri = uri }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {

        // ── File Selection ──────────────────────────────────────────────────
        Text(
            "Select Files",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface
        )

        FilePickerCard(
            label = "File to Verify",
            uri = dataUri,
            icon = Icons.Default.InsertDriveFile,
            onClick = { dataFilePicker.launch("*/*") }
        )

        FilePickerCard(
            label = "Signature File (.sig / .asc)",
            uri = sigUri,
            icon = Icons.Default.VerifiedUser,
            onClick = { sigFilePicker.launch("*/*") }
        )

        // ── Verify Button ───────────────────────────────────────────────────
        Button(
            onClick = {
                val d = dataUri ?: return@Button
                val s = sigUri ?: return@Button
                scope.launch {
                    isLoading = true
                    result = null
                    result = repo.verify(d, s, context)
                    isLoading = false
                }
            },
            enabled = dataUri != null && sigUri != null && !isLoading,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary
            )
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp
                )
                Spacer(Modifier.width(8.dp))
                Text("Verifying...")
            } else {
                Icon(Icons.Default.Shield, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Verify Signature", fontWeight = FontWeight.Bold)
            }
        }

        // ── Result ──────────────────────────────────────────────────────────
        AnimatedVisibility(visible = result != null, enter = fadeIn(), exit = fadeOut()) {
            result?.let { res ->
                VerificationResultCard(
                    result = res,
                    showRawOutput = showRawOutput,
                    onToggleRaw = { showRawOutput = !showRawOutput }
                )
            }
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
        border = CardDefaults.outlinedCardBorder().copy(
            width = if (uri != null) 1.5.dp else 1.dp
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (uri != null) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                )
                Text(
                    uri?.lastPathSegment ?: "Tap to select",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (uri != null) MaterialTheme.colorScheme.onSurface
                    else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
                )
            }
            if (uri != null) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
            }
        }
    }
}

@Composable
fun VerificationResultCard(
    result: VerificationResult,
    showRawOutput: Boolean,
    onToggleRaw: () -> Unit
) {
    val validColor = Color(0xFF4CAF50)
    val invalidColor = Color(0xFFEF5350)
    val accentColor = if (result.isValid) validColor else invalidColor

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = accentColor.copy(alpha = 0.08f)
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Status badge
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Icon(
                    if (result.isValid) Icons.Default.CheckCircle else Icons.Default.Cancel,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(32.dp)
                )
                Column {
                    Text(
                        if (result.isValid) "VALID SIGNATURE" else "INVALID SIGNATURE",
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        color = accentColor
                    )
                    if (!result.isValid && result.errorMessage != null) {
                        Text(
                            result.errorMessage,
                            style = MaterialTheme.typography.bodySmall,
                            color = invalidColor.copy(alpha = 0.8f)
                        )
                    }
                }
            }

            HorizontalDivider(color = accentColor.copy(alpha = 0.2f))

            // Detail fields
            if (result.isValid) {
                ResultField("Signed by", result.signedBy, Icons.Default.Person)
                ResultField("Fingerprint", result.fingerprint.chunked(4).joinToString(" "), Icons.Default.Fingerprint)
                if (result.timestamp.isNotBlank()) {
                    ResultField("Signed at", result.timestamp, Icons.Default.Schedule)
                }
                ResultField("Trust Level", result.trustLevel, Icons.Default.Shield)
            }

            // Raw output toggle
            TextButton(
                onClick = onToggleRaw,
                colors = ButtonDefaults.textButtonColors(contentColor = accentColor)
            ) {
                Icon(
                    if (showRawOutput) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null
                )
                Spacer(Modifier.width(4.dp))
                Text(if (showRawOutput) "Hide Raw Output" else "Show Raw Output")
            }

            if (showRawOutput) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Color(0xFF111111),
                            RoundedCornerShape(8.dp)
                        )
                        .border(1.dp, Color(0xFF333333), RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        result.rawOutput,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = Color(0xFF80FF80),
                        lineHeight = 16.sp
                    )
                }
            }
        }
    }
}

@Composable
fun ResultField(label: String, value: String, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Row(
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            icon,
            contentDescription = null,
            modifier = Modifier.size(16.dp).padding(top = 2.dp),
            tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
        )
        Column {
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
            )
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = if (label == "Fingerprint") FontFamily.Monospace else FontFamily.Default,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}
