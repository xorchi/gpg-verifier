package com.gpgverifier.ui.screens

import com.gpgverifier.R

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gpgverifier.prefs.AppPreferences
import com.gpgverifier.util.AppLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val MAX_FILE_SIZE = 2 * 1024 * 1024 // 2MB

@Composable
fun TextViewerScreen(modifier: Modifier = Modifier) {
    val context     = LocalContext.current
    val scope       = rememberCoroutineScope()
    val scrollV     = rememberScrollState()
    val scrollH     = rememberScrollState()

    var fileUri     by remember { mutableStateOf<Uri?>(null) }
    var content     by remember { mutableStateOf("") }
    var fileName    by remember { mutableStateOf("") }
    var fileSize    by remember { mutableStateOf(0L) }
    var isLoading   by remember { mutableStateOf(false) }
    var error       by remember { mutableStateOf<String?>(null) }
    var wordWrap    by remember { mutableStateOf(true) }
    var fontSize    by remember { mutableStateOf(13) }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        fileUri = uri
        scope.launch {
            isLoading = true; error = null; content = ""
            AppLogger.d("TextViewer: opening uri=$uri", AppLogger.TAG_UI)
            try {
                val result = withContext(Dispatchers.IO) {
                    val cr = context.contentResolver
                    fileName = cr.query(uri, null, null, null, null)?.use { c ->
                        val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        c.moveToFirst(); if (idx >= 0) c.getString(idx) else "unknown"
                    } ?: uri.lastPathSegment ?: "unknown"
                    val stream = cr.openInputStream(uri) ?: error("Cannot open file")
                    val bytes  = stream.readBytes(); stream.close()
                    fileSize = bytes.size.toLong()
                    if (bytes.size > MAX_FILE_SIZE) {
                        error("File too large (${bytes.size / 1024}KB > 2MB). Showing first 2MB.")
                        return@withContext String(bytes.take(MAX_FILE_SIZE).toByteArray(), Charsets.UTF_8)
                    }
                    String(bytes, Charsets.UTF_8)
                }
                AppLogger.d("TextViewer: loaded file=$fileName size=${fileSize}B lines=${result.lines().size}", AppLogger.TAG_UI)
                content = result
            } catch (e: Exception) {
                AppLogger.e("TextViewer: failed to read file — ${e.message}", AppLogger.TAG_UI)
                error = e.message ?: "Failed to read file"
            }
            isLoading = false
        }
    }

    Column(
        modifier = modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(stringResource(R.string.nav_viewer), style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface)

        // File picker
        OutlinedCard(
            onClick = { filePicker.launch("*/*") },
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(Icons.Default.FolderOpen, null,
                    tint = if (fileUri != null) MaterialTheme.colorScheme.primary
                           else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.field_input_file), style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                    Text(if (fileName.isNotBlank()) fileName else "Tap to open file",
                        style = MaterialTheme.typography.bodyMedium)
                }
                if (fileUri != null) {
                    Text(stringResource(R.string.file_size_kb, (fileSize / 1024).toInt()), style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                }
            }
        }

        if (error != null) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text(error!!, modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall)
            }
        }

        if (isLoading) {
            Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (content.isNotBlank()) {
            // Toolbar
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(stringResource(R.string.file_stats, content.lines().size, fileSize.toInt()),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    IconButton(onClick = { if (fontSize > 9) fontSize-- }, modifier = Modifier.size(32.dp)) {
                        Text("A", fontSize = 11.sp, color = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(onClick = { if (fontSize < 22) fontSize++ }, modifier = Modifier.size(32.dp)) {
                        Text("A", fontSize = 15.sp, color = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(onClick = { wordWrap = !wordWrap }, modifier = Modifier.size(32.dp)) {
                        Icon(
                            if (wordWrap) Icons.Default.WrapText else Icons.Default.Notes,
                            null, tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }

            // Content area
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(8.dp))
                    .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                val textMod = if (wordWrap)
                    Modifier.fillMaxSize().verticalScroll(scrollV)
                else
                    Modifier.fillMaxSize().verticalScroll(scrollV).horizontalScroll(scrollH)

                Text(
                    content,
                    modifier = textMod,
                    fontFamily = FontFamily.Monospace,
                    fontSize = fontSize.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    softWrap = wordWrap
                )
            }
        }
    }
}
